"""
FFusion Scheduler (FVF) for Phase 6.

Task scheduler with weight categories for invariants, economic simulation,
triage consensus, and differential regression analysis.
"""
from __future__ import annotations

import time
import asyncio
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable, Union
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
import heapq


class TaskCategory(Enum):
    """Task categories with different weights."""
    INVARIANTS_SYMBOLIC = "invariants_symbolic"
    INVARIANTS_FUZZ = "invariants_fuzz"
    ECONOMIC_SIMULATION = "economic_simulation"
    TRIAGE_CONSENSUS = "triage_consensus"
    DIFFERENTIAL_REGRESSION = "differential_regression"


class TaskPriority(Enum):
    """Task priority levels."""
    HIGH = 1
    MEDIUM = 2
    LOW = 3


@dataclass
class TaskResult:
    """Result of a scheduled task."""
    task_id: str
    category: TaskCategory
    status: str  # "completed", "failed", "timeout", "aborted"
    execution_time_ms: int
    result_data: Optional[Any] = None
    error: Optional[str] = None


@dataclass 
class ScheduledTask:
    """A task in the scheduler queue."""
    task_id: str
    category: TaskCategory
    priority: TaskPriority
    weight: float
    timeout_ms: int
    
    # Task execution
    func: Callable
    args: tuple = field(default_factory=tuple)
    kwargs: dict = field(default_factory=dict)
    
    # Scheduling metadata
    created_at: float = field(default_factory=time.time)
    estimated_duration_ms: int = 1000
    dependencies: List[str] = field(default_factory=list)
    
    def __lt__(self, other):
        """For heapq ordering by priority and weight."""
        if self.priority.value != other.priority.value:
            return self.priority.value < other.priority.value
        return self.weight > other.weight  # Higher weight = higher priority


class AdaptiveBudgetManager:
    """Manages time budget allocation with adaptive degradation."""
    
    def __init__(self, total_budget_ms: int):
        self.total_budget_ms = total_budget_ms
        self.remaining_budget_ms = total_budget_ms
        self.start_time = time.time()
        
        # Category weights (higher = more important)
        self.category_weights = {
            TaskCategory.INVARIANTS_SYMBOLIC: 1.0,
            TaskCategory.TRIAGE_CONSENSUS: 0.9,
            TaskCategory.ECONOMIC_SIMULATION: 0.8,
            TaskCategory.INVARIANTS_FUZZ: 0.7,
            TaskCategory.DIFFERENTIAL_REGRESSION: 0.6
        }
        
        # Degradation order (first to be cut when budget is low)
        self.degradation_order = [
            TaskCategory.DIFFERENTIAL_REGRESSION,
            TaskCategory.INVARIANTS_FUZZ,
            TaskCategory.ECONOMIC_SIMULATION,
            TaskCategory.TRIAGE_CONSENSUS,
            TaskCategory.INVARIANTS_SYMBOLIC
        ]
    
    def allocate_budget(self, tasks: List[ScheduledTask]) -> Dict[TaskCategory, int]:
        """Allocate budget across task categories."""
        if not tasks:
            return {}
        
        # Group tasks by category
        category_tasks: Dict[TaskCategory, List[ScheduledTask]] = {}
        for task in tasks:
            if task.category not in category_tasks:
                category_tasks[task.category] = []
            category_tasks[task.category].append(task)
        
        # Calculate estimated time needed per category
        category_estimates = {}
        for category, cat_tasks in category_tasks.items():
            total_estimate = sum(task.estimated_duration_ms for task in cat_tasks)
            category_estimates[category] = total_estimate
        
        # Allocate budget proportionally by weight and need
        total_weighted_need = sum(
            estimate * self.category_weights.get(cat, 0.5)
            for cat, estimate in category_estimates.items()
        )
        
        budget_allocation = {}
        for category, estimate in category_estimates.items():
            if total_weighted_need > 0:
                weight = self.category_weights.get(category, 0.5)
                proportion = (estimate * weight) / total_weighted_need
                allocated = int(self.remaining_budget_ms * proportion)
                budget_allocation[category] = allocated
            else:
                budget_allocation[category] = 0
        
        return budget_allocation
    
    def should_degrade(self, usage_ratio: float = 0.7) -> bool:
        """Check if budget degradation should be triggered."""
        elapsed = (time.time() - self.start_time) * 1000
        return elapsed > (self.total_budget_ms * usage_ratio)
    
    def apply_degradation(self, tasks: List[ScheduledTask]) -> List[ScheduledTask]:
        """Apply budget degradation by removing lower priority tasks."""
        if not self.should_degrade():
            return tasks
        
        # Remove tasks in degradation order
        filtered_tasks = []
        degraded_categories = set()
        
        # Calculate how many categories to degrade
        usage = (time.time() - self.start_time) * 1000 / self.total_budget_ms
        if usage > 0.9:  # Very tight budget
            degraded_categories.update(self.degradation_order[:3])
        elif usage > 0.8:  # Moderate budget pressure
            degraded_categories.update(self.degradation_order[:2])
        else:  # Light budget pressure
            degraded_categories.add(self.degradation_order[0])
        
        for task in tasks:
            if task.category not in degraded_categories:
                filtered_tasks.append(task)
        
        return filtered_tasks
    
    def consume_budget(self, amount_ms: int) -> None:
        """Consume budget allocation."""
        self.remaining_budget_ms = max(0, self.remaining_budget_ms - amount_ms)
    
    def get_budget_summary(self) -> Dict[str, Any]:
        """Get current budget status."""
        elapsed = (time.time() - self.start_time) * 1000
        return {
            "total_budget_ms": self.total_budget_ms,
            "remaining_budget_ms": self.remaining_budget_ms,
            "elapsed_ms": int(elapsed),
            "usage_ratio": elapsed / self.total_budget_ms if self.total_budget_ms > 0 else 1.0
        }


class FFusionScheduler:
    """Main fusion scheduler for Phase 6 tasks."""
    
    def __init__(self, max_workers: int = 4, default_budget_ms: int = 60000):
        self.max_workers = max_workers
        self.default_budget_ms = default_budget_ms
        self.task_queue: List[ScheduledTask] = []
        self.completed_tasks: List[TaskResult] = []
        self.running_tasks: Dict[str, ScheduledTask] = {}
        self.aborted_tasks: List[str] = []
        
        # Metrics
        self.queue_latency_samples: List[float] = []
        self.execution_counts: Dict[TaskCategory, int] = {}
        
    def schedule_task(self, task: ScheduledTask) -> None:
        """Add a task to the scheduler queue."""
        # Set weight based on category if not specified
        if task.weight == 0:
            task.weight = self._get_default_weight(task.category)
        
        heapq.heappush(self.task_queue, task)
    
    def schedule_invariant_symbolic(self, invariant_name: str, invariant_func: Callable,
                                  *args, **kwargs) -> str:
        """Schedule a symbolic invariant check."""
        task_id = f"inv_sym_{invariant_name}_{int(time.time() * 1000)}"
        task = ScheduledTask(
            task_id=task_id,
            category=TaskCategory.INVARIANTS_SYMBOLIC,
            priority=TaskPriority.HIGH,
            weight=1.0,
            timeout_ms=6000,  # 6 seconds default
            func=invariant_func,
            args=args,
            kwargs=kwargs,
            estimated_duration_ms=3000
        )
        self.schedule_task(task)
        return task_id
    
    def schedule_invariant_fuzz(self, invariant_name: str, fuzz_func: Callable,
                               *args, **kwargs) -> str:
        """Schedule a fuzz testing task."""
        task_id = f"inv_fuzz_{invariant_name}_{int(time.time() * 1000)}"
        task = ScheduledTask(
            task_id=task_id,
            category=TaskCategory.INVARIANTS_FUZZ,
            priority=TaskPriority.MEDIUM,
            weight=0.7,
            timeout_ms=15000,  # 15 seconds default
            func=fuzz_func,
            args=args,
            kwargs=kwargs,
            estimated_duration_ms=8000
        )
        self.schedule_task(task)
        return task_id
    
    def schedule_economic_simulation(self, simulation_name: str, sim_func: Callable,
                                   *args, **kwargs) -> str:
        """Schedule an economic simulation task."""
        task_id = f"econ_sim_{simulation_name}_{int(time.time() * 1000)}"
        task = ScheduledTask(
            task_id=task_id,
            category=TaskCategory.ECONOMIC_SIMULATION,
            priority=TaskPriority.MEDIUM,
            weight=0.8,
            timeout_ms=10000,  # 10 seconds default
            func=sim_func,
            args=args,
            kwargs=kwargs,
            estimated_duration_ms=5000
        )
        self.schedule_task(task)
        return task_id
    
    def schedule_triage_consensus(self, triage_name: str, triage_func: Callable,
                                *args, **kwargs) -> str:
        """Schedule a triage consensus task."""
        task_id = f"triage_{triage_name}_{int(time.time() * 1000)}"
        task = ScheduledTask(
            task_id=task_id,
            category=TaskCategory.TRIAGE_CONSENSUS,
            priority=TaskPriority.HIGH,
            weight=0.9,
            timeout_ms=8000,  # 8 seconds default
            func=triage_func,
            args=args,
            kwargs=kwargs,
            estimated_duration_ms=4000
        )
        self.schedule_task(task)
        return task_id
    
    def execute_scheduled_tasks(self, budget_ms: Optional[int] = None) -> List[TaskResult]:
        """Execute all scheduled tasks within budget."""
        if not self.task_queue:
            return []
        
        budget_manager = AdaptiveBudgetManager(budget_ms or self.default_budget_ms)
        
        # Apply budget degradation if needed
        available_tasks = budget_manager.apply_degradation(self.task_queue.copy())
        
        # Allocate budget
        budget_allocation = budget_manager.allocate_budget(available_tasks)
        
        results = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit tasks respecting budget allocation
            future_to_task = {}
            category_usage = {cat: 0 for cat in budget_allocation.keys()}
            
            for task in available_tasks:
                if task.task_id in self.aborted_tasks:
                    continue
                
                # Check budget for this category
                category_budget = budget_allocation.get(task.category, 0)
                category_used = category_usage.get(task.category, 0)
                
                if category_used + task.estimated_duration_ms <= category_budget:
                    # Submit task
                    future = executor.submit(self._execute_task, task)
                    future_to_task[future] = task
                    category_usage[task.category] += task.estimated_duration_ms
                    self.running_tasks[task.task_id] = task
                else:
                    # Abort task due to budget
                    self.aborted_tasks.append(task.task_id)
                    result = TaskResult(
                        task_id=task.task_id,
                        category=task.category,
                        status="aborted",
                        execution_time_ms=0,
                        error="Budget exceeded"
                    )
                    results.append(result)
            
            # Collect results
            for future in as_completed(future_to_task, timeout=budget_ms/1000 if budget_ms else 60):
                task = future_to_task[future]
                try:
                    result = future.result()
                    results.append(result)
                    
                    # Update metrics
                    if task.category not in self.execution_counts:
                        self.execution_counts[task.category] = 0
                    self.execution_counts[task.category] += 1
                    
                    # Calculate queue latency
                    queue_time = (time.time() - task.created_at) * 1000
                    self.queue_latency_samples.append(queue_time)
                    
                except Exception as e:
                    result = TaskResult(
                        task_id=task.task_id,
                        category=task.category,
                        status="failed",
                        execution_time_ms=0,
                        error=str(e)
                    )
                    results.append(result)
                finally:
                    if task.task_id in self.running_tasks:
                        del self.running_tasks[task.task_id]
        
        # Clear completed tasks from queue
        self.task_queue = [t for t in self.task_queue if t.task_id not in 
                          {r.task_id for r in results}]
        
        self.completed_tasks.extend(results)
        return results
    
    def _execute_task(self, task: ScheduledTask) -> TaskResult:
        """Execute a single task with timeout."""
        start_time = time.time()
        
        try:
            # Execute the task function
            result_data = task.func(*task.args, **task.kwargs)
            execution_time = int((time.time() - start_time) * 1000)
            
            return TaskResult(
                task_id=task.task_id,
                category=task.category,
                status="completed",
                execution_time_ms=execution_time,
                result_data=result_data
            )
            
        except Exception as e:
            execution_time = int((time.time() - start_time) * 1000)
            return TaskResult(
                task_id=task.task_id,
                category=task.category,
                status="failed",
                execution_time_ms=execution_time,
                error=str(e)
            )
    
    def _get_default_weight(self, category: TaskCategory) -> float:
        """Get default weight for a task category."""
        weights = {
            TaskCategory.INVARIANTS_SYMBOLIC: 1.0,
            TaskCategory.TRIAGE_CONSENSUS: 0.9,
            TaskCategory.ECONOMIC_SIMULATION: 0.8,
            TaskCategory.INVARIANTS_FUZZ: 0.7,
            TaskCategory.DIFFERENTIAL_REGRESSION: 0.6
        }
        return weights.get(category, 0.5)
    
    def get_scheduler_metrics(self) -> Dict[str, Any]:
        """Get scheduler performance metrics."""
        avg_queue_latency = (
            sum(self.queue_latency_samples) / len(self.queue_latency_samples)
            if self.queue_latency_samples else 0
        )
        
        return {
            "tasks_run": sum(self.execution_counts.values()),
            "tasks_aborted": len(self.aborted_tasks),
            "time_budget_ms": self.default_budget_ms,
            "queue_latency_avg_ms": avg_queue_latency,
            "execution_counts": dict(self.execution_counts),
            "queue_size": len(self.task_queue),
            "running_tasks": len(self.running_tasks)
        }
    
    def clear_completed_tasks(self) -> None:
        """Clear completed task history."""
        self.completed_tasks.clear()
        self.queue_latency_samples.clear()
        self.execution_counts.clear()
        self.aborted_tasks.clear()


# Example usage and utility functions
def create_sample_scheduler_config() -> Dict[str, Any]:
    """Create sample scheduler configuration."""
    return {
        "max_workers": 4,
        "time_budget_ms": 60000,  # 1 minute default
        "category_weights": {
            "invariants_symbolic": 1.0,
            "triage_consensus": 0.9,
            "economic_simulation": 0.8,
            "invariants_fuzz": 0.7,
            "differential_regression": 0.6
        },
        "degradation_thresholds": {
            "light_pressure": 0.7,    # Start degrading at 70% budget usage
            "moderate_pressure": 0.8, # More aggressive at 80%
            "heavy_pressure": 0.9     # Most aggressive at 90%
        }
    }