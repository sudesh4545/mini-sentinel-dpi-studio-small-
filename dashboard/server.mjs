import express from "express";
import OpenAI from "openai";
import "dotenv/config";
import { fileURLToPath } from "node:url";
import path from "node:path";

const app = express();
const root = path.dirname(fileURLToPath(import.meta.url));
const port = Number(process.env.PORT || 4180);
const client = process.env.OPENAI_API_KEY ? new OpenAI() : null;
const groq = process.env.GROQ_API_KEY
  ? new OpenAI({ apiKey: process.env.GROQ_API_KEY, baseURL: "https://api.groq.com/openai/v1" })
  : null;
const ollamaUrl = process.env.OLLAMA_URL || "http://127.0.0.1:11434";
const ollamaModel = process.env.OLLAMA_MODEL || "qwen3:1.7b";

const hasOllama = async () => {
  try {
    const result = await fetch(`${ollamaUrl}/api/tags`, { signal: AbortSignal.timeout(1200) });
    if (!result.ok) return false;
    const data = await result.json();
    return data.models?.some((model) => model.name === ollamaModel || model.model === ollamaModel) || false;
  } catch {
    return false;
  }
};

app.use(express.json({ limit: "300kb" }));
app.get("/api/health", async (_request, response) => {
  const local = await hasOllama();
  response.json({ ok: true, ai: local || Boolean(groq) || Boolean(client), provider: local ? "local ollama" : groq ? "groq free" : client ? "openai" : "offline analyst" });
});
app.post("/api/axiom", async (request, response) => {
  const question = String(request.body?.question || "").slice(0, 600);
  const report = request.body?.report;
  if (!question || !report?.summary || !Array.isArray(report?.flows)) {
    return response.status(400).json({ error: "A valid question and report are required" });
  }
  const safeReport = {
    summary: report.summary,
    flows: report.flows.slice(0, 200).map(({ host, application, packets, bytes, verdict, reason }) => ({
      host, application, packets, bytes, verdict, reason,
    })),
  };
  try {
    if (await hasOllama()) {
      const localResponse = await fetch(`${ollamaUrl}/api/chat`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          model: ollamaModel,
          stream: false,
          messages: [
            { role: "system", content: "You are AXIOM AI, a concise defensive network-analysis assistant. Analyze only supplied aggregate metadata. Never invent evidence, expose secrets, recommend offensive activity, or automatically apply rules. Explain uncertainty." },
            { role: "user", content: `Question: ${question}\n\nSentinelDPI report metadata:\n${JSON.stringify(safeReport)}` },
          ],
          options: { temperature: 0.2 },
        }),
        signal: AbortSignal.timeout(120000),
      });
      if (!localResponse.ok) throw new Error(`Local model returned ${localResponse.status}`);
      const localResult = await localResponse.json();
      return response.json({ answer: localResult.message?.content || "No analysis was returned.", mode: "local ai" });
    }
    if (groq) {
      const result = await groq.chat.completions.create({
        model: process.env.GROQ_MODEL || "openai/gpt-oss-20b",
        temperature: 0.2,
        messages: [
          { role: "system", content: "You are AXIOM AI, a concise defensive network-analysis assistant. Analyze only supplied aggregate metadata. Never invent evidence, expose secrets, recommend offensive activity, or automatically apply rules. Explain uncertainty." },
          { role: "user", content: `Question: ${question}\n\nSentinelDPI report metadata:\n${JSON.stringify(safeReport)}` },
        ],
      });
      return response.json({ answer: result.choices[0]?.message?.content || "No analysis was returned.", mode: "groq free" });
    }
    if (!client) return response.status(503).json({ error: "No AI provider is configured" });
    const result = await client.responses.create({
      model: process.env.OPENAI_MODEL || "gpt-5-mini",
      store: false,
      instructions: "You are AXIOM AI, a concise defensive network-analysis assistant. Analyze only the supplied aggregate metadata. Never claim access to packet payloads, invent evidence, recommend offensive activity, or automatically apply rules. Clearly label uncertainty and explain rule suggestions before offering them.",
      input: `Question: ${question}\n\nSentinelDPI report metadata:\n${JSON.stringify(safeReport)}`,
    });
    response.json({ answer: result.output_text || "No analysis was returned.", mode: "online ai" });
  } catch (error) {
    console.error("AXIOM request failed:", error instanceof Error ? error.message : error);
    response.status(502).json({ error: "AI analysis failed" });
  }
});
app.use(express.static(root));
app.listen(port, "127.0.0.1", () => console.log(`SentinelDPI + AXIOM AI: http://127.0.0.1:${port}`));
