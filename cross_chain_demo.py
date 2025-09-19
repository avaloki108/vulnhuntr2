"""
Integration test demonstrating cross-chain Web3 security analysis.
"""
from vulnhuntr.core.models import Finding, Contract, ScanContext, Severity
from vulnhuntr.core.cross_chain_analyzer import CrossChainAnalyzer
from vulnhuntr.core.llm_analysis import LLMAnalysisEngine
from vulnhuntr.detectors.bridge_security import BridgeSecurityDetector
from vulnhuntr.config.schema import LLMConfig

def demo_cross_chain_analysis():
    """Demonstrate comprehensive cross-chain security analysis."""
    print("🌐 Cross-Chain Web3 Security Analysis Demo")
    print("=" * 50)
    
    # Constants
    TEST_CONTRACT_FILE = "TestBridge.sol"
    
    # Mock contract for testing
    test_contract = Contract(
        name="TestBridge",
        file_path=TEST_CONTRACT_FILE,
        line_start=1,
        line_end=100
    )
    
    # Mock findings for LLM analysis
    test_findings = [
        Finding(
            detector="bridge_security",
            title="Centralized Bridge Authority",
            file=TEST_CONTRACT_FILE, 
            line=25,
            severity=Severity.HIGH,
            code="function mintTokens() onlyOwner { mint(amount); }",
            description="Bridge uses centralized authority for token minting",
            confidence=0.9
        ),
        Finding(
            detector="oracle_manipulation",
            title="Price Oracle Manipulation",
            file=TEST_CONTRACT_FILE,
            line=45,
            severity=Severity.CRITICAL,
            code="uint price = oracle.getPrice();",
            description="Single oracle price feed without validation",
            confidence=0.85
        )
    ]
    
    # 1. Cross-Chain Deployment Analysis
    print("\n1. 🔗 Cross-Chain Deployment Analysis")
    analyzer = CrossChainAnalyzer()
    target_chains = [1, 137, 42161]  # Ethereum, Polygon, Arbitrum
    
    cross_chain_risks = analyzer.analyze_cross_chain_deployment(
        contracts=[test_contract],
        target_chains=target_chains
    )
    
    print(f"   Found {len(cross_chain_risks)} cross-chain risks:")
    for risk in cross_chain_risks[:3]:  # Show first 3
        print(f"   • {risk.risk_type}: {risk.severity}")
        print(f"     {risk.description}")
        print(f"     Mitigation: {risk.mitigation}")
        print()
    
    # 2. Bridge Security Analysis
    print("2. 🌉 Bridge Security Analysis")
    bridge_detector = BridgeSecurityDetector()
    
    # Mock scan context
    scan_context = ScanContext(
        target_path=TEST_CONTRACT_FILE,
        contracts=[test_contract]
    )
    
    # Run bridge analysis (findings would be used in real implementation)
    list(bridge_detector.analyze(scan_context))
    print("   Bridge security scan complete")
    print(f"   Bridge detector: {bridge_detector.name}")
    print(f"   Severity: {bridge_detector.severity}")
    print(f"   Confidence: {bridge_detector.confidence}")
    
    # 3. LLM-Enhanced Analysis
    print("\n3. 🤖 LLM-Enhanced Web3 Analysis")
    
    # Mock LLM config
    llm_config = LLMConfig(
        provider="openai",
        model="gpt-4",
        api_key="test-key",
        max_tokens=2000
    )
    
    llm_engine = LLMAnalysisEngine(llm_config)
    
    # Analyze findings with Web3 context
    web3_context = {
        "defi_protocol": "AMM",
        "oracle_dependencies": ["Chainlink", "Band Protocol"],
        "cross_chain": True,
        "flash_loan_enabled": True,
        "token_standard": "ERC-20"
    }
    
    enhanced_results = []
    for finding in test_findings:
        analysis_result = llm_engine.analyze_finding(finding, web3_context)
        enhanced_results.append(analysis_result)
        print(f"   • {finding.title}")
        print(f"     Risk Assessment: {analysis_result.risk_assessment}")
        print(f"     Business Impact: {analysis_result.business_impact}")
        print(f"     DeFi Context: {analysis_result.defi_context}")
        print(f"     MEV Risk: {analysis_result.mev_vulnerability}")
        print()
    
    # 4. Generate Comprehensive Report
    print("4. 📊 Comprehensive Security Report")
    
    # Cross-chain compatibility report
    compatibility_report = analyzer.generate_chain_compatibility_report(
        contracts=[test_contract],
        target_chains=target_chains
    )
    
    # Web3 security report
    web3_report = llm_engine.generate_web3_security_report(enhanced_results)
    
    print(f"   Cross-chain risks: {compatibility_report['summary']['total_risks']}")
    print(f"   Critical risks: {compatibility_report['summary']['critical_risks']}")
    print(f"   Bridge risks: {compatibility_report['risk_categories']['bridge_related']}")
    print(f"   Oracle risks: {compatibility_report['risk_categories']['oracle_related']}")
    
    print(f"\n   Web3 analysis: {web3_report['summary']['total_findings']} findings")
    print(f"   DeFi risks: {web3_report['summary']['web3_specific_risks']['defi_related']}")
    print(f"   MEV vulnerabilities: {web3_report['summary']['web3_specific_risks']['mev_vulnerable']}")
    print(f"   Flash loan risks: {web3_report['summary']['web3_specific_risks']['flash_loan_risks']}")
    
    # 5. Final Recommendations
    print("\n5. 🛡️ Security Recommendations")
    
    immediate_actions = compatibility_report['recommendations']['immediate_action']
    defi_specific = web3_report['web3_recommendations']['defi_specific']
    
    print("   Immediate Actions:")
    for action in immediate_actions[:2]:
        print(f"   • {action}")
    
    print("\n   DeFi-Specific Measures:")
    for measure in defi_specific[:3]:
        print(f"   • {measure}")
    
    print("\n✅ Cross-chain Web3 security analysis complete!")
    print("🔍 Comprehensive coverage of bridge, oracle, MEV, and DeFi risks")
    print("🌐 Multi-chain deployment considerations analyzed")
    print("🤖 LLM-enhanced insights for Web3-specific attack vectors")
    
    return {
        "cross_chain_risks": len(cross_chain_risks),
        "enhanced_findings": len(enhanced_results),
        "overall_risk_level": "HIGH" if any(r.severity == "CRITICAL" for r in cross_chain_risks) else "MEDIUM"
    }

if __name__ == "__main__":
    result = demo_cross_chain_analysis()
    print(f"\n📈 Analysis Summary: {result}")