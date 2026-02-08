import os
from dotenv import load_dotenv
from openai import OpenAI  # We switch to the universal OpenAI client

# 1. Load environment variables
load_dotenv()
api_key = os.getenv("MY_API_KEY") # Ensure this is your OpenRouter or Together key
base_url = "https://openrouter.ai/api/v1" # Example for OpenRouter

if not api_key:
    print("ERROR: API Key not found.")
else:
    print(f"SUCCESS: Found API Key.")

# 2. Initialize Client
try:
    print("Initializing Client...")
    # We point the client to the new provider's URL
    client = OpenAI(
        base_url=base_url,
        api_key=api_key,
    )
    
    print("Sending request for MythoMax...")
    response = client.chat.completions.create(
        model="gryphe/mythomax-l2-13b",
        messages=[
            {
                "role": "user",
                "content": "Say 'Hello' if you can hear me.",
            }
        ],
    )

    print("Response:")
    print(response.choices[0].message.content)

except Exception as e:
    print(f"ERROR: Connection failed. Details: {e}")