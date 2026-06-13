/// <reference lib="webworker" />
/**
 * Analysis Web Worker — all parsing, scanning and cleansing happens here so
 * multi-megabyte saves never block the UI thread. The parsed save is kept in
 * worker memory between messages so cleansing doesn't re-parse or re-transfer
 * the file.
 */
import { analyzeParsedSave, cleanseSave, parseSave, TtsParseError, type ParsedSave } from './analyzer';
import type { WorkerRequest, WorkerResponse } from './models';

let currentParsed: ParsedSave | null = null;

const post = (msg: WorkerResponse) => postMessage(msg);

addEventListener('message', async ({ data }: MessageEvent<WorkerRequest>) => {
  try {
    switch (data.type) {
      case 'analyze': {
        currentParsed = null;
        const parsed = parseSave(data.jsonText);
        const result = await analyzeParsedSave(
          parsed,
          data.fileName,
          data.jsonText.length,
          new Set(data.safeHashes),
          (processed, total) => post({ type: 'progress', processed, total }),
        );
        currentParsed = parsed;
        post({ type: 'result', requestId: data.requestId, result });
        break;
      }

      case 'cleanse': {
        if (!currentParsed) throw new Error('No analyzed save in memory — run an analysis first.');
        const outcome = cleanseSave(currentParsed);
        post({ type: 'cleansed', requestId: data.requestId, outcome });
        break;
      }

      case 'getScript': {
        const script = currentParsed?.nodes[data.nodeId]?.script ?? '';
        post({ type: 'script', requestId: data.requestId, nodeId: data.nodeId, script });
        break;
      }
    }
  } catch (e) {
    const message =
      e instanceof TtsParseError
        ? e.message
        : `Unexpected error while processing the file: ${(e as Error).message}`;
    post({ type: 'error', requestId: data.requestId, message });
  }
});
