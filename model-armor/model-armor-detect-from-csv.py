import csv
import requests
import json
import time
import google.auth
from google.auth.transport.requests import AuthorizedSession

# ==========================================
# 參數設定區 (請根據您的環境填寫)
# ==========================================
# 輸入與輸出檔案名稱
INPUT_CSV = 'Test_Prompt.csv'
OUTPUT_CSV = 'Test_Prompt_Result.csv'

# Model Armor 設定參數
PROJECT_ID = 'xxx' # 輸入GCP Project ID
LOCATION = 'xxx' # 輸入 Model Armor template location (e.g. us-central1)
TEMPLATE_NAME = 'xxx' # 輸入 Model Armor Template 名稱

# Model Armor RESTful API 端點自動產生
API_URL = f'https://modelarmor.{LOCATION}.rep.googleapis.com/v1alpha/projects/{PROJECT_ID}/locations/{LOCATION}/templates/{TEMPLATE_NAME}:sanitizeUserPrompt'

# ==========================================
# 認證設定 (使用 Google Cloud ADC)
# ==========================================
# 程式將自動抓取 Application Default Credentials
# 執行前請確保已透過 gcloud cli 登入: `gcloud auth application-default login`
try:
    credentials, project_id = google.auth.default(scopes=['https://www.googleapis.com/auth/cloud-platform'])
    authed_session = AuthorizedSession(credentials)
except Exception as e:
    print(f"[錯誤] 無法載入 Google Cloud ADC 憑證: {e}")
    print("請確定您已設定環境變數 GOOGLE_APPLICATION_CREDENTIALS 或已執行 `gcloud auth application-default login`")
    exit(1)

# ==========================================
# API 呼叫函數
# ==========================================
def check_prompt_with_model_armor(prompt_text):
    """
    呼叫 Model Armor API 檢查 Prompt。
    回傳 Tuple: (是否觸發攔截(Yes/No), 觸發的類型字串)
    """
    if not prompt_text.strip():
        return "No", ""

    # 1. 準備 API 請求的 Payload 
    # 根據 sanitizeUserPrompt 端點，通常 payload 需包裝在 userPromptData 中
    payload = {
         "userPromptData": {"text": prompt_text}
    }

    try:
        # 使用包含 ADC 認證的 session 發送請求
        response = authed_session.post(API_URL, json=payload, timeout=10)
        
        # 若發生 HTTP 錯誤會拋出異常
        response.raise_for_status() 
        
        result = response.json()

        # 2. 解析 API 回應 (依據提供的 JSON 格式)
        matched_types = []
        sanitization_result = result.get('sanitizationResult', {})
        
        # 判斷總體是否 Match
        if sanitization_result.get('filterMatchState') == 'MATCH_FOUND':
            match_yes_no = "Yes"
        else:
            match_yes_no = "No"

        filter_results = sanitization_result.get('filterResults', {})

        # --- 檢查各種類型的 Filter ---
        
        # 1. CSAM
        if filter_results.get('csam', {}).get('csamFilterFilterResult', {}).get('matchState') == 'MATCH_FOUND':
            matched_types.append('csam')
            
        # 2. Malicious URIs
        if filter_results.get('malicious_uris', {}).get('maliciousUriFilterResult', {}).get('matchState') == 'MATCH_FOUND':
            matched_types.append('malicious_uris')
            
        # 3. RAI (Responsible AI) - 包含多個子類別 (dangerous, harassment, hate_speech, sexually_explicit)
        rai_type_results = filter_results.get('rai', {}).get('raiFilterResult', {}).get('raiFilterTypeResults', {})
        for r_type, r_data in rai_type_results.items():
            if r_data.get('matchState') == 'MATCH_FOUND':
                matched_types.append(f'rai_{r_type}')
                
        # 4. PI and Jailbreak
        if filter_results.get('pi_and_jailbreak', {}).get('piAndJailbreakFilterResult', {}).get('matchState') == 'MATCH_FOUND':
            matched_types.append('pi_and_jailbreak')
            
        # 5. SDP (Sensitive Data Protection)
        sdp_result = filter_results.get('sdp', {}).get('sdpFilterResult', {})
        # SDP 根據設定不同，可能回傳 inspectResult 或 deidentifyResult，因此兩者都要檢查
        if sdp_result.get('inspectResult', {}).get('matchState') == 'MATCH_FOUND' or \
           sdp_result.get('deidentifyResult', {}).get('matchState') == 'MATCH_FOUND':
            
            # 嘗試提取觸發的敏感資料類型 (infoTypes)，例如 LOCATION
            info_types = sdp_result.get('deidentifyResult', {}).get('infoTypes', [])
            if info_types:
                matched_types.append(f"sdp({','.join(info_types)})")
            else:
                matched_types.append('sdp')

        matched_types_str = ", ".join(matched_types)

        return match_yes_no, matched_types_str

    except requests.exceptions.RequestException as e:
        print(f"[錯誤] 呼叫 API 失敗，Prompt: '{prompt_text[:20]}...' | 錯誤訊息: {e}")
        # 若發生錯誤，回傳 Error 以便在 CSV 中辨識
        return "Error", str(e)

# ==========================================
# 主程式區塊
# ==========================================
def main():
    print(f"開始讀取檔案: {INPUT_CSV} ...")
    
    updated_rows = []
    
    try:
        # 讀取 CSV
        with open(INPUT_CSV, mode='r', encoding='utf-8-sig') as infile:
            reader = csv.DictReader(infile)
            
            # 確保欄位名稱正確 (根據您上傳的檔案結構)
            fieldnames = reader.fieldnames
            if 'Match (Yes, No)' not in fieldnames or 'Matched Types' not in fieldnames:
                print("[警告] 找不到目標欄位，將自動嘗試補齊欄位。")
                if 'Match (Yes, No)' not in fieldnames: fieldnames.append('Match (Yes, No)')
                if 'Matched Types' not in fieldnames: fieldnames.append('Matched Types')

            for row_num, row in enumerate(reader, start=1):
                prompt = row.get('Test Prompt', '')
                
                print(f"[{row_num}] 正在檢查: {prompt[:20]}...")
                
                # 呼叫 API 取得結果
                match_status, match_types = check_prompt_with_model_armor(prompt)
                
                # 更新行資料
                row['Match (Yes, No)'] = match_status
                row['Matched Types'] = match_types
                
                updated_rows.append(row)
                
                # 避免請求過於頻繁觸發 Rate Limit，可根據需求加入延遲
                time.sleep(0.2) 

        # 寫入新的 CSV
        with open(OUTPUT_CSV, mode='w', encoding='utf-8-sig', newline='') as outfile:
            writer = csv.DictWriter(outfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(updated_rows)
            
        print(f"\n✅ 處理完成！結果已儲存至: {OUTPUT_CSV}")

    except FileNotFoundError:
        print(f"[錯誤] 找不到檔案 {INPUT_CSV}，請確認檔案與程式在同一目錄。")
    except Exception as e:
        print(f"[錯誤] 程式執行發生異常: {e}")

if __name__ == "__main__":
    main()
