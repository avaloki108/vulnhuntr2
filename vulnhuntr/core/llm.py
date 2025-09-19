"""
LLM integration for vulnerability triage and explanation.
"""

import os
import json
from typing import Dict, List, Optional, Any, Union
import logging
from pathlib import Path

import openai
from tenacity import retry, stop_after_attempt, wait_exponential

from vulnhuntr.core.registry import Finding

logger = logging.getLogger(__name__)

class LLMClient:
    """Base class for LLM integrations."""
    
    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-4"):
        self.api_key = api_key or os.getenv("VULNHUNTR_LLM_API_KEY")
        self.model = model
        
        if not self.api_key:
            logger.warning("No API key provided for LLM client. Some features will be disabled.")
    
    def is_configured(self) -> bool:
        """Check if the LLM client is properly configured."""
        return bool(self.api_key)
    
    def analyze_finding(self, finding: Finding, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a finding using LLM to get additional insights.
        
        Args:
            finding: The vulnerability finding
            context: Additional context information
            
        Returns:
            Dictionary with analysis results
        """
        raise NotImplementedError("LLM clients must implement analyze_finding")

class OpenAIClient(LLMClient):
    """OpenAI GPT integration for vulnerability analysis."""
    
    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-4"):
        super().__init__(api_key, model)
        if self.api_key:
            openai.api_key = self.api_key
    
    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=10))
    def _call_openai(self, messages: List[Dict[str, str]], temperature: float = 0.3) -> str:
        """Make a request to OpenAI API with retry logic."""
        if not self.is_configured():
            raise ValueError("OpenAI API key is not configured")
        
        try:
            response = openai.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=temperature,
                max_tokens=1024,
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"Error calling OpenAI API: {e}")
            raise
    
    def analyze_finding(self, finding: Finding, context: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a finding using GPT to get additional insights."""
        if not self.is_configured():
            return {"error": "OpenAI API key not configured"}
        
        # Extract code context
        code_context = context.get("code_context", "")
        file_path = finding.file
        
        # Craft the prompt
        messages = [
            {"role": "system", "content": (
                "You are a smart contract security expert analyzing potential vulnerabilities. "
                "Provide a technical assessment of the finding, including: "
                "1. Is this a true positive or likely false positive? "
                "2. Detailed explanation of the vulnerability "
                "3. Severity assessment (Critical, High, Medium, Low, Informational) "
                "4. Exploitation scenario "
                "5. Recommended fix "
                "\nBe precise and technical. If you need more information, indicate what's missing."
            )},
            {"role": "user", "content": (
                f"Finding: {finding.title} ({finding.severity})\n"
                f"Detector: {finding.detector}\n"
                f"File: {file_path}\n"
                f"Line: {finding.line}\n"
                f"Code: ```solidity\n{code_context}\n```\n\n"
                "Please analyze this finding."
            )}
        ]
        
        try:
            response_text = self._call_openai(messages)
            
            # Extract structured information
            analysis = {
                "explanation": response_text,
                "source": "openai",
                "model": self.model,
            }
            
            # Try to parse severity rating from the response
            severity_mapping = {
                "critical": "CRITICAL", 
                "high": "HIGH", 
                "medium": "MEDIUM", 
                "low": "LOW", 
                "informational": "INFO"
            }
            
            for sev_text, sev_code in severity_mapping.items():
                if sev_text in response_text.lower():
                    analysis["suggested_severity"] = sev_code
                    break
            else:
                analysis["suggested_severity"] = None
                
            # Detect true/false positive assessment
            if "false positive" in response_text.lower():
                analysis["false_positive_likelihood"] = "high"
            elif "likely false" in response_text.lower():
                analysis["false_positive_likelihood"] = "medium"
            elif "true positive" in response_text.lower():
                analysis["false_positive_likelihood"] = "low"
            else:
                analysis["false_positive_likelihood"] = "unknown"
                
            return analysis
            
        except Exception as e:
            logger.error(f"Error during LLM analysis: {e}")
            return {
                "error": str(e),
                "source": "openai",
                "model": self.model,
            }

# Factory function to create the appropriate LLM client
def create_llm_client(provider: str = "openai", api_key: Optional[str] = None, 
                     model: Optional[str] = None) -> LLMClient:
    """Create an LLM client based on the specified provider."""
    
    if provider.lower() == "openai":
        return OpenAIClient(api_key=api_key, model=model or "gpt-4")
    else:
        raise ValueError(f"Unsupported LLM provider: {provider}")