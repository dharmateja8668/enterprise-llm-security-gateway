class MockLLMService:
    async def generate_response(self, prompt: str) -> str:
        """
        A simple mock LLM service that returns a static response.
        This keeps the architecture modular for when real providers are added.
        """
        return "This is a mock LLM response."
