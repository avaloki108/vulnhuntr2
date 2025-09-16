"""
Basic tests for Phase 6 functionality.
"""
import pytest
from pathlib import Path
from vulnhuntr.core.models import Finding, Severity


class TestPhase6Features:
    """Test Phase 6 features."""
    
    def test_multi_chain_config_loading(self):
        """Test multi-chain configuration loading."""
        from vulnhuntr.core.multi_chain import MultiChainContextLoader
        
        # Test with non-existent file
        loader = MultiChainContextLoader(Path("nonexistent.yaml"))
        assert not loader.load_config()
        assert len(loader.chains) == 0
        assert len(loader.bridges) == 0
        assert len(loader.oracles) == 0
    
    def test_invariant_parser(self):
        """Test invariant DSL parser."""
        from vulnhuntr.core.invariants import InvariantParser, InvariantType
        
        parser = InvariantParser()
        
        # Test expression validation
        valid, error = parser.validate_expression("a + b >= a && a + b >= b")
        assert valid
        assert error is None
        
        invalid, error = parser.validate_expression("a + b >= a && (")
        assert not invalid
        assert "parentheses" in error.lower()
    
    def test_risk_model_calculation(self):
        """Test risk model calculations."""
        from vulnhuntr.core.risk_model import RiskFactors, RiskCalculator
        
        factors = RiskFactors(
            reachability=0.8,
            invariant_violation=0.5,
            economic_feasibility=0.7,
            consensus_alignment=0.9
        )
        
        calculator = RiskCalculator()
        p_exploit = calculator.calculate_p_exploit(factors)
        
        # Should be between 0 and 1
        assert 0.0 <= p_exploit <= 1.0
        
        # Higher factors should generally lead to higher probability
        low_factors = RiskFactors(
            reachability=0.1,
            invariant_violation=0.0,
            economic_feasibility=0.1,
            consensus_alignment=0.9
        )
        
        p_exploit_low = calculator.calculate_p_exploit(low_factors)
        assert p_exploit > p_exploit_low
    
    def test_exploit_simulation(self):
        """Test exploit scenario simulation."""
        from vulnhuntr.core.exploit_simulation import ExploitScenarioSimulator, MarketConditions
        
        # Create mock finding
        finding = Finding(
            detector="test_detector",
            title="Test Vulnerability",
            file="test.sol",
            line=42,
            severity=Severity.HIGH,
            code="function withdraw() { /* vulnerable code */ }",
            contract_name="TestContract",
            function_name="withdraw"
        )
        
        market_conditions = MarketConditions()
        simulator = ExploitScenarioSimulator(market_conditions)
        
        scenario = simulator.simulate_exploit_scenario(finding)
        
        # Basic validation
        assert scenario.scenario_id is not None
        assert scenario.exploit_type is not None
        assert scenario.capital_requirements is not None
        assert scenario.payoff_estimate is not None
        assert 0.0 <= scenario.feasibility_score <= 1.0
    
    def test_knowledge_graph_building(self):
        """Test knowledge graph building."""
        from vulnhuntr.core.knowledge_graph import KnowledgeGraphBuilder, NodeType
        
        builder = KnowledgeGraphBuilder()
        
        # Build empty graph
        graph = builder.build_from_contracts([])
        
        assert graph.get_stats()["total_nodes"] == 0
        assert graph.get_stats()["total_edges"] == 0
        assert graph.get_stats()["build_time_ms"] >= 0
    
    def test_plugin_attestation(self):
        """Test plugin attestation manager."""
        from vulnhuntr.core.plugin_attestation import PluginAttestationManager
        import tempfile
        
        with tempfile.TemporaryDirectory() as temp_dir:
            lock_file = Path(temp_dir) / "test_plugins.lock"
            manager = PluginAttestationManager(lock_file)
            
            # Test initial state
            summary = manager.get_attestation_summary()
            assert summary["total_plugins"] == 0
            
            # Test listing empty attestations
            attestations = manager.list_attestations()
            assert len(attestations) == 0
    
    def test_policy_engine(self):
        """Test policy engine."""
        from vulnhuntr.core.policy_engine import PolicyConfiguration, PolicyEngine, SeverityPolicy
        
        # Create basic policy
        policy = PolicyConfiguration(
            enabled=True,
            severity=SeverityPolicy(
                enabled=True,
                min_severity="HIGH",
                max_findings=5
            )
        )
        
        engine = PolicyEngine(policy)
        
        # Test with no findings
        result = engine.evaluate_findings([])
        assert result.compliant
        assert len(result.violations) == 0
        
        # Test with high severity finding
        high_severity_finding = Finding(
            detector="test",
            title="Critical Issue",
            file="test.sol",
            line=1,
            severity=Severity.CRITICAL,
            code="critical code"
        )
        
        result = engine.evaluate_findings([high_severity_finding])
        assert not result.compliant
        assert len(result.violations) > 0
    
    def test_ffusion_scheduler(self):
        """Test FFusion scheduler."""
        from vulnhuntr.core.ffusion_scheduler import FFusionScheduler, TaskCategory, TaskPriority, ScheduledTask
        
        scheduler = FFusionScheduler(max_workers=2, default_budget_ms=5000)
        
        # Test simple task scheduling
        def dummy_task():
            return "completed"
        
        task = ScheduledTask(
            task_id="test_task",
            category=TaskCategory.INVARIANTS_SYMBOLIC,
            priority=TaskPriority.HIGH,
            weight=1.0,
            timeout_ms=1000,
            func=dummy_task
        )
        
        scheduler.schedule_task(task)
        assert len(scheduler.task_queue) == 1
        
        # Execute tasks
        results = scheduler.execute_scheduled_tasks(budget_ms=2000)
        assert len(results) == 1
        assert results[0].status == "completed"
        assert results[0].result_data == "completed"
    
    def test_bridge_oracle_risk_analysis(self):
        """Test bridge and oracle risk analysis."""
        from vulnhuntr.core.bridge_oracle_risk import BridgeRiskAnalyzer, OracleRiskAnalyzer
        from vulnhuntr.core.multi_chain import ChainMetadata, BridgeMetadata, OracleMetadata
        
        # Create test data
        chains = {
            1: ChainMetadata(chain_id=1, name="Ethereum", finality_blocks=12),
            137: ChainMetadata(chain_id=137, name="Polygon", finality_blocks=128)
        }
        
        bridges = [
            BridgeMetadata(
                name="Test Bridge",
                source_chain_id=1,
                target_chain_id=137,
                delay_blocks=100
            )
        ]
        
        oracles = [
            OracleMetadata(
                name="Test Oracle",
                feed_address="0x123...",
                chain_id=1,
                asset_pair="ETH/USD",
                heartbeat_seconds=3600
            )
        ]
        
        # Test bridge analysis
        bridge_analyzer = BridgeRiskAnalyzer(chains, bridges)
        bridge_patterns = bridge_analyzer.analyze_all_bridges()
        assert len(bridge_patterns) == 1
        assert bridge_patterns[0].pattern_type == "finality_delay"
        
        # Test oracle analysis
        oracle_analyzer = OracleRiskAnalyzer(oracles)
        oracle_patterns = oracle_analyzer.analyze_all_oracles()
        assert len(oracle_patterns) == 2  # heartbeat + divergence patterns