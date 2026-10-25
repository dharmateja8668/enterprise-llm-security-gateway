export interface PIISummary {
  pii_detected: boolean;
  count: number;
  entity_types: string[];
}

export type SecurityBlockType =
  | 'injection'
  | 'rbac'
  | 'content_safety'
  | 'rate_limit'
  | 'auth'
  | 'error';

export interface ChatMessage {
  id: string;
  role: 'user' | 'assistant' | 'system';
  content: string;
  timestamp: string;
  isBlocked?: boolean;
  blockReason?: string;
  blockType?: SecurityBlockType;
  piiSummary?: PIISummary;
  model?: string;
  latencyMs?: number;
}

export interface ChatSession {
  id: string;
  title: string;
  createdAt: string;
  messages: ChatMessage[];
}

export interface GatewayHealth {
  status: string;
  ollamaReachable?: boolean;
  model?: string;
  modelAvailable?: boolean;
}

export interface UserRecord {
  id: number;
  username: string;
  email: string;
  department?: string;
  role: string;
  is_active: boolean;
}

export interface GatewayAuth {
  apiKey: string;
  userId: string;
  user?: UserRecord;
  allowedModels?: string[];
  apiUrl: string;
}
