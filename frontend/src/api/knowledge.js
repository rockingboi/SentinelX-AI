// SentinelX AI — Knowledge Intelligence API client (Phase 3)
import api from './client'

export const knowledgeAPI = {
  /**
   * Hybrid semantic + BM25 search over the knowledge base.
   * POST /api/v1/knowledge/search
   */
  search: (payload) =>
    api.post('/api/v1/knowledge/search', payload, { timeout: 30000 }),

  /**
   * Qdrant collection + BM25 index statistics.
   * GET /api/v1/knowledge/stats
   */
  getStats: () =>
    api.get('/api/v1/knowledge/stats'),

  /**
   * Ingest a single file (admin only).
   * POST /api/v1/knowledge/ingest/file
   */
  ingestFile: (filePath) =>
    api.post('/api/v1/knowledge/ingest/file', { file_path: filePath }, { timeout: 120000 }),

  /**
   * Batch-ingest a directory (admin only).
   * POST /api/v1/knowledge/ingest/directory
   */
  ingestDirectory: (dirPath = null, recursive = true) =>
    api.post('/api/v1/knowledge/ingest/directory',
      { dir_path: dirPath, recursive },
      { timeout: 300000 }
    ),

  /**
   * Rebuild the in-memory BM25 sparse index (admin only).
   * POST /api/v1/knowledge/index/rebuild
   */
  rebuildIndex: () =>
    api.post('/api/v1/knowledge/index/rebuild', {}, { timeout: 60000 }),
}
