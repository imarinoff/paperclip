import { describe, expect, it } from "vitest";
import express from "express";
import request from "supertest";
import { boardMutationGuard } from "../middleware/board-mutation-guard.js";

function createApp(actorType: "board" | "agent", boardSource: "session" | "local_implicit" = "session") {
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    req.actor = actorType === "board"
      ? { type: "board", userId: "board", source: boardSource }
      : { type: "agent", agentId: "agent-1" };
    next();
  });
  app.use(boardMutationGuard());
  app.post("/mutate", (_req, res) => {
    res.status(204).end();
  });
  app.get("/read", (_req, res) => {
    res.status(204).end();
  });
  return app;
}

describe("boardMutationGuard", () => {
  it("allows safe methods for board actor", async () => {
    const app = createApp("board");
    const res = await request(app).get("/read");
    expect(res.status).toBe(204);
  });

  it("blocks board mutations without trusted origin", async () => {
    const app = createApp("board");
    const res = await request(app).post("/mutate").send({ ok: true });
    expect(res.status).toBe(403);
    expect(res.body).toEqual({ error: "Board mutation requires trusted browser origin" });
  });

  it("allows local implicit board mutations without origin", async () => {
    const app = createApp("board", "local_implicit");
    const res = await request(app).post("/mutate").send({ ok: true });
    expect(res.status).toBe(204);
  });

  it("allows board mutations from trusted origin", async () => {
    const app = createApp("board");
    const res = await request(app)
      .post("/mutate")
      .set("Origin", "http://localhost:3100")
      .send({ ok: true });
    expect(res.status).toBe(204);
  });

  it("allows board mutations from trusted referer origin", async () => {
    const app = createApp("board");
    const res = await request(app)
      .post("/mutate")
      .set("Referer", "http://localhost:3100/issues/abc")
      .send({ ok: true });
    expect(res.status).toBe(204);
  });

  it("does not block authenticated agent mutations", async () => {
    const app = createApp("agent");
    const res = await request(app).post("/mutate").send({ ok: true });
    expect(res.status).toBe(204);
  });

  it("allows board mutations from PAPERCLIP_PUBLIC_URL origin", async () => {
    process.env.PAPERCLIP_PUBLIC_URL = "https://paperclip.example.com";
    try {
      const app = createApp("board");
      const res = await request(app)
        .post("/mutate")
        .set("Origin", "https://paperclip.example.com")
        .send({ ok: true });
      expect(res.status).toBe(204);
    } finally {
      delete process.env.PAPERCLIP_PUBLIC_URL;
    }
  });

  it("allows board mutations from X-Forwarded-Host origin", async () => {
    const app = createApp("board");
    const res = await request(app)
      .post("/mutate")
      .set("X-Forwarded-Host", "paperclip.example.com")
      .set("Origin", "https://paperclip.example.com")
      .send({ ok: true });
    expect(res.status).toBe(204);
  });
});
