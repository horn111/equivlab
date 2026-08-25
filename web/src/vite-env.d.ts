/// <reference types="vite/client" />

declare module '*.py?raw' {
  const source: string
  export default source
}

declare module '*.css'

interface ImportMetaEnv {
  readonly VITE_NETWORK_NAME?: string
  readonly VITE_REGISTRY_ADDRESS?: string
  readonly VITE_GENLAYER_RPC_URL?: string
  readonly VITE_EXPLORER_BASE_URL?: string
  readonly VITE_DEMO_REPOSITORY?: string
  readonly VITE_DEMO_COMMIT?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}

interface Window {
  ethereum?: {
    request(args: { method: string; params?: unknown[] }): Promise<unknown>
  }
}
