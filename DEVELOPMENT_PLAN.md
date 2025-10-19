# VulnHuntr2 - Iterative Development Plan

**Last Updated:** October 19, 2025  
**Status:** Active Development  
**Current Phase:** Phase 5 Stabilization

---

## Overview

This document outlines the iterative development process for VulnHuntr2, following the evaluation that determined the tool has **genuine promise** and should proceed with focused development.

---

## Development Philosophy

### Principles
1. **Incremental Progress:** Ship small, tested improvements frequently
2. **User-Centric:** Prioritize features that provide immediate value
3. **Quality First:** Maintain >95% test coverage and zero critical bugs
4. **Community-Driven:** Open source development with clear contribution paths
5. **Performance-Aware:** Profile and optimize continuously

### Success Metrics
- **Velocity:** 2-3 significant features per sprint (2 weeks)
- **Quality:** All tests passing, linted, type-checked
- **Documentation:** Every feature documented before merge
- **Performance:** No regression >5% on baseline benchmarks

---

## Iteration 1: Foundation Fixes (Week 1)

### Objectives
Fix immediate issues and establish development workflow

### Tasks
- [x] Complete comprehensive evaluation report
- [ ] Fix test failure in `test_list_detectors` (assertion mismatch)
- [ ] Add missing `aiohttp` dependency for elite detector
- [ ] Set up automated CI/CD pipeline
- [ ] Create development documentation (CONTRIBUTING.md)
- [ ] Add performance baseline benchmarks

### Acceptance Criteria
- All 68 tests passing (no failures)
- CI pipeline green on every commit
- Development docs reviewed by 2+ people
- Performance baseline established and documented

### Estimated Duration: 3-5 days

---

## Iteration 2: Phase 5 Core (Weeks 2-3)

### Objectives
Stabilize extensibility features and plugin framework

### Tasks

#### Plugin Framework
- [ ] Complete plugin isolation tests
- [ ] Implement time & memory budgets for plugins
- [ ] Add plugin fault injection tests
- [ ] Document plugin development guide

#### Diff/Incremental Scanning
- [ ] Implement `--diff-base` functionality
- [ ] Add regression detection (removed findings)
- [ ] Create diff classification tests
- [ ] Optimize for changed-only scanning

#### SARIF Export
- [ ] Validate SARIF schema compliance
- [ ] Add GitHub Code Scanning integration test
- [ ] Document SARIF usage in CI/CD
- [ ] Create example GitHub Actions workflow

### Acceptance Criteria
- Plugins can be loaded, executed, and isolated safely
- Diff scanning reduces runtime by >50% on 10% code change
- SARIF output accepted by GitHub Code Scanning
- Documentation complete for all features

### Estimated Duration: 2 weeks

---

## Iteration 3: Phase 5 Polish (Week 4)

### Objectives
Complete Phase 5 and prepare for Phase 6

### Tasks

#### Rule DSL
- [ ] Implement rule file hot-reload
- [ ] Add conflict detection and warnings
- [ ] Create rule validation tests
- [ ] Document rule syntax and examples

#### LLM Triage
- [ ] Finalize caching mechanism
- [ ] Add hallucination detection
- [ ] Implement redaction for sensitive data
- [ ] Document triage configuration

#### Documentation
- [ ] plugins.md - Plugin development guide
- [ ] diff.md - Incremental scanning guide
- [ ] rules.md - Rule DSL reference
- [ ] triage.md - LLM triage configuration
- [ ] sarif.md - SARIF export guide

### Acceptance Criteria
- Phase 4 vs Phase 5 parity test passes (features disabled)
- All documentation reviewed and published
- Performance overhead <50ms with features disabled
- User feedback incorporated from early adopters

### Estimated Duration: 1 week

---

## Iteration 4: Phase 6 Foundation (Weeks 5-6)

### Objectives
Build core intelligence layer components

### Tasks

#### Invariant System
- [ ] Implement Invariant DSL parser
- [ ] Add invariant validator
- [ ] Create symbolic quick-check engine
- [ ] Build auto-suggest heuristics (basic)
- [ ] Document invariant specification

#### Knowledge Graph
- [ ] Build graph construction engine
- [ ] Add Contract/Function/StateVar nodes
- [ ] Implement calls/reads/writes edges
- [ ] Create graph query interface
- [ ] Add graph visualization export (DOT)

#### Multi-Chain Support
- [ ] Implement chain configuration parser
- [ ] Add address normalization (chainId:address)
- [ ] Create cross-chain pattern rules
- [ ] Document multi-chain setup

### Acceptance Criteria
- Invariants can be declared and validated
- Knowledge graph built for test contracts
- Multi-chain configuration parsed correctly
- Documentation includes examples for each feature

### Estimated Duration: 2 weeks

---

## Iteration 5: Phase 6 Intelligence (Weeks 7-8)

### Objectives
Add advanced analysis and risk modeling

### Tasks

#### Economic Simulation
- [ ] Implement capital requirement estimator
- [ ] Add exploit payoff calculator
- [ ] Build feasibility classifier
- [ ] Document economic model assumptions

#### Risk Modeling
- [ ] Implement probability calculation (p_exploit)
- [ ] Add expected loss estimation
- [ ] Create risk CSV export
- [ ] Document risk model formulas

#### Policy Engine
- [ ] Build policy parser and validator
- [ ] Implement exit code mapping
- [ ] Add policy evaluation report
- [ ] Create policy examples

### Acceptance Criteria
- Economic feasibility attached to relevant findings
- Risk metrics calculated with documented assumptions
- Policy engine enforces configured rules
- All features documented with examples

### Estimated Duration: 2 weeks

---

## Iteration 6: Community & Polish (Weeks 9-10)

### Objectives
Build community and prepare for broader adoption

### Tasks

#### Community Building
- [ ] Create comprehensive documentation site
- [ ] Write tutorial blog posts
- [ ] Record demo videos
- [ ] Set up community forum/Discord
- [ ] Create contribution guidelines

#### Quality Improvements
- [ ] Achieve 95%+ test coverage
- [ ] Performance optimization pass
- [ ] False positive reduction initiative
- [ ] Security audit of tool itself

#### Examples & Templates
- [ ] GitHub Actions workflow templates
- [ ] Sample invariants files
- [ ] Policy configuration examples
- [ ] Multi-chain setup examples

### Acceptance Criteria
- Documentation site live and searchable
- 3+ tutorial videos published
- Test coverage >95%
- Community channels active with >50 members

### Estimated Duration: 2 weeks

---

## Iteration 7: Enterprise Features (Weeks 11-12)

### Objectives
Add features for professional and enterprise users

### Tasks

#### Advanced Features
- [ ] Plugin attestation system
- [ ] Consensus triage (multi-model)
- [ ] Advanced correlation patterns
- [ ] Custom detector templates

#### Integration & Automation
- [ ] VS Code extension (basic)
- [ ] Pre-commit hooks
- [ ] CI/CD templates for major platforms
- [ ] API for programmatic access

#### Reporting
- [ ] PDF report generation
- [ ] Customizable report templates
- [ ] Executive summary mode
- [ ] Compliance mapping (OWASP, etc.)

### Acceptance Criteria
- Enterprise features documented and tested
- Integration examples working on major platforms
- Professional-quality reports generated
- User feedback positive from enterprise beta users

### Estimated Duration: 2 weeks

---

## Beyond 12 Weeks: Continuous Improvement

### Phase 7+ Features (Prioritized by User Demand)
1. **Runtime Monitoring** - Post-deployment security tracking
2. **Formal Verification Integration** - hevm, Certora hooks
3. **Cross-Chain Advanced** - Complex bridge analysis
4. **ML-Enhanced Detection** - Pattern learning from known exploits
5. **Automated Remediation** - Generate fix PRs
6. **Protocol Templates** - DeFi-specific detector bundles

### Ongoing Activities
- **Weekly:** Community engagement, issue triage
- **Bi-weekly:** Performance profiling and optimization
- **Monthly:** Security review, dependency updates
- **Quarterly:** Roadmap review and user surveys

---

## Success Milestones

### 3 Months
- ✅ Phase 5 complete and stable
- ✅ Phase 6 MVP launched
- ✅ 100+ GitHub stars
- ✅ 1,000+ scans performed
- ✅ 5+ community contributors

### 6 Months
- ✅ 30+ active detectors
- ✅ 500+ GitHub stars
- ✅ 10,000+ scans performed
- ✅ 3+ audit firm partnerships
- ✅ Published academic paper

### 12 Months
- ✅ Industry-standard pre-audit tool
- ✅ 1,000+ GitHub stars
- ✅ 100,000+ scans performed
- ✅ Self-sustaining through premium features
- ✅ Expansion to other blockchain ecosystems

---

## Risk Management

### Technical Risks
| Risk | Mitigation | Status |
|------|------------|--------|
| Performance degradation | Continuous profiling, incremental scanning | Monitored |
| False positive rate | Multi-detector correlation, user feedback | Improving |
| Dependency issues | Regular updates, alternative implementations | Managed |
| LLM costs | Caching, rate limiting, local models | Controlled |

### Business Risks
| Risk | Mitigation | Status |
|------|------------|--------|
| Slow adoption | Strong docs, GitHub integration, community | Active |
| Competition | Unique features, faster iteration | Differentiating |
| Funding | Multiple revenue streams, grants | Exploring |

---

## Resource Allocation

### Development Team (Current)
- **Core Development:** 1-2 engineers
- **Documentation:** 1 technical writer (part-time)
- **Community:** 1 community manager (part-time)

### Tool Stack
- **Development:** Python 3.12, VSCode, Git
- **Testing:** pytest, coverage, mutation testing
- **CI/CD:** GitHub Actions
- **Documentation:** Markdown, MkDocs
- **Community:** Discord, GitHub Discussions

---

## Review & Adaptation

### Weekly Reviews
- Progress against iteration goals
- Blocker identification and resolution
- Community feedback integration
- Performance metrics review

### Monthly Reviews
- Roadmap alignment check
- KPI assessment
- Resource reallocation if needed
- Stakeholder updates

### Quarterly Reviews
- Major roadmap adjustments
- Market analysis and competitive positioning
- User survey and feedback synthesis
- Strategic direction confirmation

---

## Appendix: Detailed Task Breakdown

### Iteration 1: Foundation Fixes

#### Fix test_list_detectors
**Estimated Time:** 1 hour  
**Complexity:** Low  
**Dependencies:** None

1. Review test expectation in `tests/test_cli.py`
2. Update assertion to match actual output
3. Verify test passes locally
4. Commit with clear message

#### Add aiohttp dependency
**Estimated Time:** 30 minutes  
**Complexity:** Low  
**Dependencies:** None

1. Add `aiohttp` to `pyproject.toml` under appropriate section
2. Update documentation if needed
3. Test elite detector loads without error
4. Commit dependency update

#### Setup CI/CD
**Estimated Time:** 4 hours  
**Complexity:** Medium  
**Dependencies:** None

1. Create `.github/workflows/ci.yml`
2. Add jobs: test, lint, type-check, security-scan
3. Configure matrix testing (Python versions)
4. Add status badges to README
5. Test pipeline on PR

---

**Status:** Living document - Updated with each iteration  
**Maintainer:** Development Team  
**Review Schedule:** Weekly
