import type { Metadata, Viewport } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'SwissKnife - Backend-First Next.js Template',
  description: 'Compact backend-first template with authentication, users API, validation, and middleware foundations.',
  keywords: ['swissknife', 'nextjs', 'typescript', 'api-template', 'authentication'],
  authors: [{ name: 'SwissKnife' }],
  icons: {
    icon: '/favicon.ico',
  },
};

export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
  maximumScale: 1,
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className="bg-background text-foreground antialiased">
        {children}
      </body>
    </html>
  );
}
