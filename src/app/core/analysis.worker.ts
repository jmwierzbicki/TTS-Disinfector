/// <reference lib="webworker" />
/**
 * Analysis Web Worker — all parsing, scanning and cleansing happens here so
 * multi-megabyte saves (and large batches of saved objects) never block the UI
 * thread. The parsed documents are kept in worker memory between messages so
 * cleansing doesn't re-parse or re-transfer the files.
 */
import {
  analyzeDocuments,
  cleanseDocuments,
  parseSave,
  TtsParseError,
  type AnalyzableDoc,
} from './analyzer';
import type { WorkerRequest, WorkerResponse } from './models';

let currentDocs: AnalyzableDoc[] = [];

const post = (msg: WorkerResponse) => postMessage(msg);

addEventListener('message', async ({ data }: MessageEvent<WorkerRequest>) => {
  try {
    switch (data.type) {
      case 'analyze': {
        currentDocs = [];
        const docs: AnalyzableDoc[] = [];
        const skipped: { fileName: string; reason: string }[] = [];

        for (const file of data.files) {
          try {
            docs.push({ parsed: parseSave(file.text), fileName: file.name, byteSize: file.text.length });
          } catch (e) {
            const reason = e instanceof TtsParseError ? e.message : (e as Error).message;
            skipped.push({ fileName: file.name, reason });
          }
        }

        // If nothing parsed, surface the error (single-file behaviour preserved).
        if (docs.length === 0) {
          const only = skipped[0];
          throw new TtsParseError(
            data.files.length === 1 && only
              ? only.reason
              : `None of the ${data.files.length} files could be read as TTS saves or saved objects.`,
          );
        }

        const result = await analyzeDocuments(
          docs,
          skipped,
          new Set(data.safeHashes),
          (processed, total) => post({ type: 'progress', processed, total }),
        );
        currentDocs = docs;
        post({ type: 'result', requestId: data.requestId, result });
        break;
      }

      case 'cleanse': {
        if (currentDocs.length === 0) throw new Error('No analyzed files in memory — run an analysis first.');
        const outcome = cleanseDocuments(currentDocs);
        post({ type: 'cleansed', requestId: data.requestId, outcome });
        break;
      }

      case 'getScript': {
        const script = currentDocs[data.docId]?.parsed.nodes[data.nodeId]?.script ?? '';
        post({ type: 'script', requestId: data.requestId, script });
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
