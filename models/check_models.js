import 'dotenv/config';
import { GoogleGenerativeAI } from "@google/generative-ai";

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

async function listModels() {
  try {
    const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });
    // We use the generic listModels method to see what's available
    // (Note: The SDK doesn't have a direct listModels method exposed easily in all versions, 
    // so we will use the raw REST API to be 100% sure).

    const key = process.env.GEMINI_API_KEY;
    const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models?key=${key}`);
    const data = await response.json();

    console.log("\n=== 🟢 AVAILABLE MODELS FOR YOUR KEY ===");
    if (data.models) {
        data.models.forEach(m => {
            // Only show models that generate text/chat
            if(m.supportedGenerationMethods.includes("generateContent")) {
                console.log(`✅ ${m.name.replace("models/", "")}`);
            }
        });
    } else {
        console.log("❌ No models found. Error:", data.error?.message);
    }
    console.log("========================================\n");
  } catch (err) {
    console.error("Error:", err);
  }
}

listModels();