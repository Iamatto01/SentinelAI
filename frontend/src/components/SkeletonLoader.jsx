import React from 'react'

/**
 * Single animated shimmer bar. Use as the building block for all skeletons.
 */
export function Skeleton({ className = '', rounded = 'rounded-lg' }) {
  return (
    <div
      className={`skeleton-shimmer ${rounded} ${className}`}
      aria-hidden="true"
    />
  )
}

/**
 * Dashboard — 4 stat cards + 3-column chart row
 */
export function DashboardSkeleton() {
  return (
    <div className="space-y-6 animate-in fade-in duration-200">
      {/* Header banner */}
      <div className="rounded-3xl p-6 sm:p-7 border border-white/10 bg-slate-900/60 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="flex items-center gap-4">
          <Skeleton className="w-14 h-14" rounded="rounded-2xl" />
          <div className="space-y-2">
            <Skeleton className="h-6 w-64" />
            <Skeleton className="h-4 w-96 max-w-full" />
          </div>
        </div>
        <div className="flex items-center gap-3">
          <Skeleton className="h-8 w-28" rounded="rounded-full" />
          <Skeleton className="h-8 w-24" rounded="rounded-full" />
          <Skeleton className="h-8 w-28" rounded="rounded-full" />
        </div>
      </div>

      {/* 4 Stat cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {[...Array(4)].map((_, i) => (
          <div key={i} className="rounded-3xl p-5 border border-white/10 bg-slate-900/60 space-y-3">
            <div className="flex items-center justify-between">
              <Skeleton className="h-4 w-28" />
              <Skeleton className="h-11 w-11" rounded="rounded-2xl" />
            </div>
            <Skeleton className="h-8 w-20" />
            <Skeleton className="h-3 w-32" rounded="rounded-full" />
            <Skeleton className="h-1 w-full" rounded="rounded-full" />
          </div>
        ))}
      </div>

      {/* Balanced 2/3 and 1/3 layout */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column (2/3) */}
        <div className="lg:col-span-2 space-y-6">
          <div className="rounded-3xl p-6 sm:p-7 border border-white/10 bg-slate-900/60 space-y-6">
            <div className="flex items-center justify-between">
              <Skeleton className="h-5 w-48" />
              <Skeleton className="h-6 w-28" rounded="rounded-full" />
            </div>
            <div className="grid grid-cols-1 md:grid-cols-12 gap-6 items-center">
              <div className="md:col-span-5 flex justify-center">
                <Skeleton className="w-52 h-52" rounded="rounded-full" />
              </div>
              <div className="md:col-span-7 space-y-3">
                {[...Array(5)].map((_, i) => (
                  <Skeleton key={i} className="h-12 w-full" rounded="rounded-2xl" />
                ))}
              </div>
            </div>
          </div>

          <div className="rounded-3xl p-6 sm:p-7 border border-white/10 bg-slate-900/60 space-y-4">
            <div className="flex items-center justify-between">
              <Skeleton className="h-5 w-48" />
              <Skeleton className="h-6 w-28" rounded="rounded-full" />
            </div>
            {[...Array(4)].map((_, i) => (
              <div key={i} className="flex items-center justify-between p-4 rounded-2xl border border-white/5">
                <div className="flex items-center gap-3 flex-1">
                  <Skeleton className="w-11 h-11" rounded="rounded-2xl" />
                  <div className="space-y-1.5 flex-1 mr-3">
                    <Skeleton className="h-3.5 w-3/4" />
                    <Skeleton className="h-2.5 w-1/3" />
                  </div>
                </div>
                <Skeleton className="h-6 w-20" rounded="rounded-full" />
              </div>
            ))}
          </div>
        </div>

        {/* Right Column (1/3) */}
        <div className="lg:col-span-1 space-y-6">
          <div className="rounded-3xl p-6 sm:p-7 border border-white/10 bg-slate-900/60 space-y-4">
            <Skeleton className="h-5 w-32" />
            <Skeleton className="w-36 h-36 mx-auto" rounded="rounded-full" />
            <Skeleton className="h-2 w-full" rounded="rounded-full" />
            <div className="space-y-2 pt-2">
              <Skeleton className="h-10 w-full" rounded="rounded-2xl" />
              <Skeleton className="h-10 w-full" rounded="rounded-2xl" />
              <Skeleton className="h-10 w-full" rounded="rounded-2xl" />
            </div>
          </div>

          <div className="rounded-3xl p-6 sm:p-7 border border-white/10 bg-slate-900/60 space-y-3">
            <Skeleton className="h-5 w-32" />
            <div className="grid grid-cols-2 gap-3">
              {[...Array(4)].map((_, i) => (
                <Skeleton key={i} className="h-24 w-full" rounded="rounded-2xl" />
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

/**
 * Scans page — folder groups + scan rows
 */
export function ScanListSkeleton() {
  return (
    <div className="space-y-4 animate-in fade-in duration-200">
      {/* Header */}
      <div className="card p-5 border-white/10 flex items-center justify-between">
        <div className="space-y-2">
          <Skeleton className="h-7 w-48" />
          <Skeleton className="h-4 w-72" />
        </div>
        <Skeleton className="h-10 w-32" rounded="rounded-xl" />
      </div>

      {/* Toolbar */}
      <div className="flex gap-3">
        <Skeleton className="h-10 flex-1 max-w-sm" rounded="rounded-xl" />
        <Skeleton className="h-10 w-24" rounded="rounded-xl" />
        <Skeleton className="h-10 w-24" rounded="rounded-xl" />
      </div>

      {/* Folder groups */}
      {[...Array(2)].map((_, gi) => (
        <div key={gi} className="card border-white/10 overflow-hidden">
          {/* Folder header */}
          <div className="flex items-center gap-3 px-4 py-3 border-b border-white/10">
            <Skeleton className="h-5 w-5" rounded="rounded" />
            <Skeleton className="h-4 w-32" />
            <Skeleton className="h-4 w-12 ml-2" rounded="rounded-full" />
          </div>
          {/* Scan rows */}
          {[...Array(3)].map((_, ri) => (
            <div key={ri} className="flex items-center gap-4 px-4 py-3.5 border-b border-white/[0.04] last:border-0">
              <Skeleton className="h-4 w-4 shrink-0" rounded="rounded" />
              <div className="flex-1 space-y-1.5 min-w-0">
                <Skeleton className="h-3.5 w-48 max-w-full" />
                <Skeleton className="h-2.5 w-32" />
              </div>
              <Skeleton className="h-5 w-16" rounded="rounded-full" />
              <Skeleton className="h-5 w-12" rounded="rounded-full" />
              <Skeleton className="h-7 w-7" rounded="rounded-lg" />
            </div>
          ))}
        </div>
      ))}
    </div>
  )
}

/**
 * Findings page — filter bar + finding rows
 */
export function FindingSkeleton({ rows = 8 }) {
  return (
    <div className="space-y-4 animate-in fade-in duration-200">
      {/* Header */}
      <div className="card p-5 border-white/10 flex items-center justify-between">
        <div className="space-y-2">
          <Skeleton className="h-7 w-52" />
          <Skeleton className="h-4 w-80 max-w-full" />
        </div>
        <Skeleton className="h-9 w-28" rounded="rounded-xl" />
      </div>

      {/* Filter bar */}
      <div className="card p-3 border-white/10 flex flex-wrap gap-2">
        <Skeleton className="h-9 flex-1 min-w-[180px]" rounded="rounded-xl" />
        {[...Array(4)].map((_, i) => <Skeleton key={i} className="h-9 w-28" rounded="rounded-xl" />)}
      </div>

      {/* Table */}
      <div className="card border-white/10 overflow-hidden">
        {/* Header */}
        <div className="flex items-center gap-3 px-4 py-2.5 border-b border-white/10">
          {[52, 28, 20, 16, 12].map((w, i) => (
            <Skeleton key={i} className={`h-3 w-${w} hidden sm:block`} />
          ))}
        </div>
        {/* Rows */}
        {[...Array(rows)].map((_, i) => (
          <div key={i} className="flex items-center gap-3 px-4 py-3 border-b border-white/[0.04] last:border-0">
            <Skeleton className="h-5 w-16 shrink-0" rounded="rounded-full" />
            <div className="flex-1 space-y-1.5 min-w-0">
              <Skeleton className="h-3.5 w-56 max-w-full" />
              <Skeleton className="h-2.5 w-32" />
            </div>
            <Skeleton className="h-5 w-20 shrink-0" rounded="rounded-full" />
            <Skeleton className="h-5 w-24 shrink-0 hidden md:block" rounded="rounded-full" />
            <div className="flex gap-1.5 shrink-0">
              <Skeleton className="h-7 w-7" rounded="rounded-lg" />
              <Skeleton className="h-7 w-7" rounded="rounded-lg" />
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

/**
 * Billing page skeleton
 */
export function BillingSkeleton() {
  return (
    <div className="space-y-8 animate-in fade-in duration-200 pb-16">
      {/* Header */}
      <div className="card p-6 border-white/10 flex items-center justify-between">
        <div className="space-y-2">
          <Skeleton className="h-7 w-64" />
          <Skeleton className="h-4 w-96 max-w-full" />
        </div>
        <Skeleton className="h-10 w-28" rounded="rounded-xl" />
      </div>

      {/* Subscription status card */}
      <div className="card p-6 border-white/10 space-y-5">
        <div className="flex justify-between items-center pb-4 border-b border-white/10">
          <div className="space-y-2">
            <Skeleton className="h-3 w-40" />
            <Skeleton className="h-7 w-48" />
          </div>
          <Skeleton className="h-7 w-28" rounded="rounded-full" />
        </div>
        <div className="space-y-2">
          <div className="flex justify-between">
            <Skeleton className="h-3 w-36" />
            <Skeleton className="h-3 w-32" />
          </div>
          <Skeleton className="h-3 w-full" rounded="rounded-full" />
        </div>
      </div>

      {/* Plans */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {[...Array(2)].map((_, i) => (
          <div key={i} className="card p-8 border-white/10 space-y-6">
            <Skeleton className="h-6 w-36" />
            <Skeleton className="h-10 w-24" />
            <div className="space-y-2">
              {[...Array(5)].map((_, j) => <Skeleton key={j} className="h-4 w-full" />)}
            </div>
            <Skeleton className="h-11 w-full" rounded="rounded-xl" />
          </div>
        ))}
      </div>
    </div>
  )
}

/**
 * Generic list skeleton (configurable)
 */
export function ListSkeleton({ rows = 5, showHeader = true }) {
  return (
    <div className="space-y-3 animate-in fade-in duration-200">
      {showHeader && (
        <div className="flex items-center justify-between">
          <Skeleton className="h-7 w-48" />
          <Skeleton className="h-9 w-28" rounded="rounded-xl" />
        </div>
      )}
      <div className="card border-white/10 overflow-hidden">
        {[...Array(rows)].map((_, i) => (
          <div key={i} className="flex items-center gap-4 px-4 py-3.5 border-b border-white/[0.05] last:border-0">
            <Skeleton className="h-8 w-8 shrink-0" rounded="rounded-xl" />
            <div className="flex-1 space-y-1.5">
              <Skeleton className="h-3.5 w-48 max-w-full" />
              <Skeleton className="h-2.5 w-24" />
            </div>
            <Skeleton className="h-6 w-16" rounded="rounded-full" />
            <Skeleton className="h-7 w-7" rounded="rounded-lg" />
          </div>
        ))}
      </div>
    </div>
  )
}
