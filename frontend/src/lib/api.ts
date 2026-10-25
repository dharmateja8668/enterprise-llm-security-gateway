import { PIISummary, SecurityBlockType, UserRecord, ChatSession } from './types';

export const DEFAULT_GATEWAY_URL = 'http://127.0.0.1:8081';
export const DEFAULT_API_KEY = 'dev-gateway-key-llama3';

export interface ChatApiSuccess {
  success: true;
  response: string;
  model: string;
  chat_id?: string;
  pii_summary?: PIISummary;
}

export interface ChatApiError {
  success: false;
  statusCode: number;
  message: string;
  blockType?: SecurityBlockType;
  detail?: any;
}

export type ChatApiResponse = ChatApiSuccess | ChatApiError;

export interface LoginApiSuccess {
  success: true;
  access_token: string;
  user: UserRecord;
  allowed_models: string[];
}

export interface LoginApiError {
  success: false;
  statusCode: number;
  message: string;
}

export type LoginApiResponse = LoginApiSuccess | LoginApiError;

export async function loginToGateway(
  usernameOrEmail: string,
  password: string,
  baseUrl: string = DEFAULT_GATEWAY_URL
): Promise<LoginApiResponse> {
  const cleanBaseUrl = baseUrl.replace(/\/+$/, '');
  const endpoint = `${cleanBaseUrl}/auth/login`;

  try {
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        username_or_email: usernameOrEmail.trim(),
        password: password,
      }),
    });

    const data = await response.json().catch(() => null);

    if (response.ok && data?.success) {
      return {
        success: true,
        access_token: data.access_token || DEFAULT_API_KEY,
        user: data.user,
        allowed_models: data.allowed_models || ['llama3.2:3b'],
      };
    }

    const detailMsg = typeof data?.detail === 'string' ? data.detail : 'Invalid username or password.';
    return {
      success: false,
      statusCode: response.status,
      message: detailMsg,
    };
  } catch (err: any) {
    return {
      success: false,
      statusCode: 0,
      message: `Could not connect to Zaalima Gateway at ${cleanBaseUrl}. Make sure backend is running.`,
    };
  }
}

export async function logoutGateway(
  apiKey: string = DEFAULT_API_KEY,
  baseUrl: string = DEFAULT_GATEWAY_URL
): Promise<boolean> {
  const cleanBaseUrl = baseUrl.replace(/\/+$/, '');
  try {
    await fetch(`${cleanBaseUrl}/auth/logout`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
      },
    });
    return true;
  } catch {
    return false;
  }
}

export async function fetchUserChats(
  apiKey: string = DEFAULT_API_KEY,
  userId: string = '',
  baseUrl: string = DEFAULT_GATEWAY_URL
): Promise<ChatSession[]> {
  const cleanBaseUrl = baseUrl.replace(/\/+$/, '');
  try {
    const response = await fetch(`${cleanBaseUrl}/chats?user_id=${encodeURIComponent(userId)}`, {
      headers: {
        'Authorization': `Bearer ${apiKey}`,
      },
      cache: 'no-store',
    });
    if (response.ok) {
      return await response.json();
    }
    return [];
  } catch {
    return [];
  }
}

export async function createUserChat(
  title: string = 'New Security Chat',
  apiKey: string = DEFAULT_API_KEY,
  userId: string = '',
  baseUrl: string = DEFAULT_GATEWAY_URL
): Promise<ChatSession | null> {
  const cleanBaseUrl = baseUrl.replace(/\/+$/, '');
  try {
    const response = await fetch(`${cleanBaseUrl}/chats?user_id=${encodeURIComponent(userId)}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`,
      },
      body: JSON.stringify({ title }),
    });
    if (response.ok) {
      return await response.json();
    }
    return null;
  } catch {
    return null;
  }
}

export async function deleteUserChat(
  chatId: string,
  apiKey: string = DEFAULT_API_KEY,
  userId: string = '',
  baseUrl: string = DEFAULT_GATEWAY_URL
): Promise<boolean> {
  const cleanBaseUrl = baseUrl.replace(/\/+$/, '');
  try {
    const response = await fetch(`${cleanBaseUrl}/chats/${chatId}?user_id=${encodeURIComponent(userId)}`, {
      method: 'DELETE',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
      },
    });
    return response.ok;
  } catch {
    return false;
  }
}

export async function sendPromptToGateway(
  prompt: string,
  apiKey: string = DEFAULT_API_KEY,
  userId?: string,
  chatId?: string,
  baseUrl: string = DEFAULT_GATEWAY_URL
): Promise<ChatApiResponse> {
  const cleanBaseUrl = baseUrl.replace(/\/+$/, '');
  const endpoint = `${cleanBaseUrl}/chat`;

  try {
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey.trim()}`,
      },
      body: JSON.stringify({
        prompt: prompt,
        user_id: userId && userId.trim() ? userId.trim() : undefined,
        chat_id: chatId || undefined,
      }),
    });

    const data = await response.json().catch(() => null);

    if (response.ok && data?.success) {
      return {
        success: true,
        response: data.response || '',
        model: data.model || 'llama3.2:3b',
        chat_id: data.chat_id,
        pii_summary: data.pii_summary,
      };
    }

    // Process error statuses
    const status = response.status;
    let blockType: SecurityBlockType = 'error';
    let errorMessage = '⚠️ An unexpected error occurred while processing your request.';

    if (status === 401) {
      blockType = 'auth';
      errorMessage = '⚠️ Authentication failed. Please verify your Zaalima Gateway API key.';
    } else if (status === 429) {
      blockType = 'rate_limit';
      const detailMsg = typeof data?.detail === 'string' ? data.detail : '';
      errorMessage = `⚠️ Request blocked: ${detailMsg || 'Rate limit exceeded (10 requests per minute limit reached).'}`;
    } else if (status === 403) {
      const detailObj = typeof data?.detail === 'object' ? data.detail : null;
      const detailStr = typeof data?.detail === 'string' ? data.detail : '';

      if (detailObj?.reason === 'chat_owner_mismatch' || detailStr.includes('do not own')) {
        blockType = 'rbac';
        errorMessage = `⚠️ Access Denied: You do not own this chat thread.`;
      } else if (detailObj?.reason?.includes('injection') || detailObj?.error?.toLowerCase().includes('injection') || detailStr.includes('injection')) {
        blockType = 'injection';
        const reason = detailObj?.reason || 'Prompt injection pattern detected in input prompt';
        errorMessage = `⚠️ This request was blocked by the Zaalima Security Gateway. (Reason: ${reason})`;
      } else if (detailObj?.reason === 'rbac_model_access_denied' || detailObj?.error?.includes('access denied')) {
        blockType = 'rbac';
        errorMessage = `⚠️ Access Denied: your department is not authorized to use this AI model.`;
      } else if (detailObj?.error?.includes('content safety') || detailStr.includes('content safety')) {
        blockType = 'content_safety';
        const category = detailObj?.category ? ` [Category: ${detailObj.category}]` : '';
        errorMessage = `⚠️ This response was blocked by the Zaalima Security Gateway content safety policy${category}.`;
      } else {
        blockType = 'error';
        errorMessage = `⚠️ Request blocked by Zaalima Security Gateway policy.`;
      }
    } else if (status === 400) {
      const detailMsg = typeof data?.detail === 'string' ? data.detail : 'Invalid prompt input.';
      errorMessage = `⚠️ Invalid input: ${detailMsg}`;
    } else if (status === 500) {
      blockType = 'error';
      const detailMsg = typeof data?.detail === 'string' ? data.detail : '';
      errorMessage = `⚠️ Request blocked: ${detailMsg || 'Security scanning failure. Request rejected for safety.'}`;
    } else if (data?.detail) {
      errorMessage = `⚠️ Gateway Error (${status}): ${typeof data.detail === 'string' ? data.detail : JSON.stringify(data.detail)}`;
    }

    return {
      success: false,
      statusCode: status,
      message: errorMessage,
      blockType,
      detail: data?.detail,
    };
  } catch (err: any) {
    return {
      success: false,
      statusCode: 0,
      message: `⚠️ Gateway Unreachable: Could not connect to FastAPI Gateway at ${cleanBaseUrl}. Make sure the backend server is running on port 8081.`,
      blockType: 'error',
    };
  }
}

export async function checkGatewayHealth(baseUrl: string = DEFAULT_GATEWAY_URL) {
  const cleanBaseUrl = baseUrl.replace(/\/+$/, '');
  try {
    const healthRes = await fetch(`${cleanBaseUrl}/health`, { cache: 'no-store' });
    const healthOk = healthRes.ok;

    let ollamaInfo = null;
    try {
      const ollamaRes = await fetch(`${cleanBaseUrl}/health/ollama`, { cache: 'no-store' });
      if (ollamaRes.ok) {
        ollamaInfo = await ollamaRes.json();
      }
    } catch {}

    return {
      healthy: healthOk,
      ollama: ollamaInfo,
    };
  } catch {
    return { healthy: false, ollama: null };
  }
}
