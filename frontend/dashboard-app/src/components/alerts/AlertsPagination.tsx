import "./AlertsPagination.css";

interface AlertsPaginationProps {
  total: number;
  limit: number;
  offset: number;
  onOffsetChange: (offset: number) => void;
}

type PageToken = number | "ellipsis";

function buildPageTokens(currentPage: number, totalPages: number): PageToken[] {
  if (totalPages <= 7) return Array.from({ length: totalPages }, (_, i) => i + 1);

  const tokens = new Set<number>([1, totalPages, currentPage, currentPage - 1, currentPage + 1]);
  const sorted = [...tokens].filter((p) => p >= 1 && p <= totalPages).sort((a, b) => a - b);

  const result: PageToken[] = [];
  let prev = 0;
  for (const page of sorted) {
    if (prev && page - prev > 1) result.push("ellipsis");
    result.push(page);
    prev = page;
  }
  return result;
}

/** Pagination driven entirely by the DataProvider's own limit/offset/total (GET /api/alerts). */
export function AlertsPagination({ total, limit, offset, onOffsetChange }: AlertsPaginationProps) {
  const totalPages = Math.max(1, Math.ceil(total / limit));
  const currentPage = Math.min(totalPages, Math.floor(offset / limit) + 1);
  const rangeStart = total === 0 ? 0 : offset + 1;
  const rangeEnd = Math.min(total, offset + limit);

  function goToPage(page: number) {
    onOffsetChange((page - 1) * limit);
  }

  return (
    <div className="table-footer">
      <span className="showing">
        Showing {rangeStart}–{rangeEnd} of {total} alerts
      </span>
      <div className="pagination">
        <button className="pg-btn" disabled={currentPage <= 1} onClick={() => goToPage(currentPage - 1)} aria-label="Previous page">
          ‹
        </button>
        {buildPageTokens(currentPage, totalPages).map((token, index) =>
          token === "ellipsis" ? (
            <span key={`ellipsis-${index}`} className="pg-ellipsis">
              …
            </span>
          ) : (
            <button
              key={token}
              className={`pg-btn${token === currentPage ? " active" : ""}`}
              onClick={() => goToPage(token)}
              aria-current={token === currentPage ? "page" : undefined}
            >
              {token}
            </button>
          ),
        )}
        <button
          className="pg-btn"
          disabled={currentPage >= totalPages}
          onClick={() => goToPage(currentPage + 1)}
          aria-label="Next page"
        >
          ›
        </button>
      </div>
    </div>
  );
}
