import React from 'react';

export const Skeleton: React.FC<{ className?: string }> = ({ className = 'h-4 w-full' }) => (
  <div className={`animate-pulse rounded bg-sunken/80 ${className}`} aria-hidden />
);

export const SkeletonRow: React.FC<{ columns?: number }> = ({ columns = 6 }) => (
  <tr className="border-b border-line animate-pulse">
    {Array.from({ length: columns }).map((_, i) => (
      <td key={i} className="td">
        <div className="h-4 bg-sunken/80 rounded w-full" />
      </td>
    ))}
  </tr>
);
