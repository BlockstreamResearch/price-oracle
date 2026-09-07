import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/operators": {
        target: process.env.OPERATOR_API_TARGET ?? "http://127.0.0.1:9100",
        changeOrigin: true,
      },
    },
  },
});
