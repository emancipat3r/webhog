package expand

import (
	"context"
	"sort"
	"sync"

	"github.com/emancipat3r/webhog/internal/renderer"
)

// Options selects what an Expander does.
type Options struct {
	SourceMaps    bool  // follow sourceMappingURL comments
	ProbeMaps     bool  // when no comment names a map, try <script>.map
	IncludeVendor bool  // mine node_modules sources embedded in maps too
	MaxMapBytes   int64 // cap on one map download (0 = DefaultMaxMapBytes)
	Chunks        bool  // discover and fetch lazily loaded chunks
	MaxChunks     int   // cap on chunks fetched per target (0 = DefaultMaxChunks)
	// Wayback asks the Wayback Machine for the scripts it captured under
	// the target's host and fetches the ones the live page no longer loads.
	Wayback         bool
	WaybackArchived bool   // fetch the archived copies instead of the live URLs
	MaxWayback      int    // cap per target (0 = DefaultMaxWayback)
	WaybackBase     string // CDX and archive origin (tests)
}

// Stats counts what the expansion did for one target.
type Stats struct {
	ChunksFetched  int // chunks fetched (any status)
	ChunksCapped   int // chunk candidates not fetched because of MaxChunks
	MapsTried      int // map URLs requested or decoded inline
	MapsExposed    int // of those, real source maps
	WaybackFetched int // historical scripts fetched (live or archived)
}

// Expander wraps a Renderer for one target: after each page renders it
// fetches the chunks and source maps the page's scripts lead to, so the
// scanner sees them as ordinary blobs. State (what was already fetched)
// is per target, which is why the caller creates one per session.
type Expander struct {
	inner         renderer.Renderer
	fetch         *Fetcher
	opts          Options
	fetchedChunks map[string]bool
	seenMapScript map[string]bool
	seenMapURL    map[string]bool
	stats         Stats
	waybackDone   bool
	mu            sync.Mutex
}

// New wraps r. The Expander is not safe for concurrent Render calls; the
// crawler's workers are, so Render serialises on a mutex internally.
func New(r renderer.Renderer, f *Fetcher, opts Options) *Expander {
	if opts.MaxChunks == 0 {
		opts.MaxChunks = DefaultMaxChunks
	}
	if opts.MaxMapBytes == 0 {
		opts.MaxMapBytes = DefaultMaxMapBytes
	}
	return &Expander{
		inner:         r,
		fetch:         f,
		opts:          opts,
		fetchedChunks: map[string]bool{},
		seenMapScript: map[string]bool{},
		seenMapURL:    map[string]bool{},
	}
}

// Stats returns the counters so far.
func (e *Expander) Stats() Stats {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.stats
}

// Render renders the page with the inner renderer, then expands it.
func (e *Expander) Render(ctx context.Context, targetURL string) (*renderer.RenderResult, error) {
	res, err := e.inner.Render(ctx, targetURL)
	if err != nil || res == nil {
		return res, err
	}
	e.Expand(ctx, res)
	return res, nil
}

// Expand widens an already rendered result in place.
func (e *Expander) Expand(ctx context.Context, res *renderer.RenderResult) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.opts.Wayback {
		e.waybackFor(ctx, res)
	}
	if e.opts.Chunks {
		e.chunksFor(ctx, res)
	}
	if e.opts.SourceMaps {
		e.sourceMapsFor(ctx, res)
	}
}

// chunksFor fetches chunk candidates until none are new or the cap is hit.
// Fetched chunks are inputs to the next round, because a chunk names the
// chunks it imports.
func (e *Expander) chunksFor(ctx context.Context, res *renderer.RenderResult) {
	for round := 0; round < 8; round++ {
		cands := chunkCandidates(res, e.fetchedChunks)
		if len(cands) == 0 {
			return
		}
		sort.Strings(cands)
		for i, u := range cands {
			if e.stats.ChunksFetched >= e.opts.MaxChunks {
				// Count what the cap left behind, once, and stop: a further
				// round would only find these same candidates again.
				e.stats.ChunksCapped += len(cands) - i
				return
			}
			if ctx.Err() != nil {
				return
			}
			e.fetchedChunks[u] = true
			e.stats.ChunksFetched++
			body, status, err := e.fetch.get(ctx, u, 0)
			if err != nil {
				res.Errors = append(res.Errors, renderer.ResourceError{URL: u, Err: err.Error()})
				continue
			}
			res.JSBlobs = append(res.JSBlobs, renderer.JSBlob{Source: "chunk", Path: u, Body: body, Status: status})
		}
	}
}
