import "./globals.css";

export const metadata = {
  title: "LinkLens | Understand website safety",
  description: "A beginner-friendly way to understand website safety.",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
