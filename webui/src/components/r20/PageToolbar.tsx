import React from 'react';

export function PageToolbar({ title, children }: { title: string; children?: React.ReactNode }) {
  return <header className="wb-page-toolbar"><h2>{title}</h2>{children}</header>;
}
