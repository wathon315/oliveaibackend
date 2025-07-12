Backend
npm install
npm run dev


🔑 How to Get google-credentials.json
Step 1: Go to Google Cloud Console
👉 https://console.cloud.google.com/
Step 2: Create/Select Project

Click "Select a project" → "New Project"
Name it: "olive-ai-skincare"
Click "Create"

Step 3: Enable Vision API

Go to "APIs & Services" → "Library"
Search for "Vision API"
Click "Cloud Vision API"
Click "Enable"

Step 4: Create Service Account

Go to "APIs & Services" → "Credentials"
Click "Create Credentials" → "Service Account"
Name: "olive-ai-service"
Click "Create and Continue"
Skip roles (click "Continue")
Click "Done"

Step 5: Download the JSON Key

Click on your service account name
Go to "Keys" tab
Click "Add Key" → "Create New Key"
Select "JSON" format
Click "Create"

📥 This downloads a JSON file like:
olive-ai-skincare-abc123def456.json
Step 6: Rename and Place

Rename the downloaded file to: google-credentials.json
Put it in your project folder: