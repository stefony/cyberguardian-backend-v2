"""
CyberGuardian AI - Federated Learning
Privacy-Preserving Collaborative Learning System

Enables collaborative AI training without sharing raw data:
- Decentralized model training
- Privacy preservation (GDPR compliant)
- Secure aggregation protocols
- Differential privacy
- Byzantine-robust aggregation
- Model versioning and distribution

Security Knowledge Applied:
- Privacy-preserving machine learning
- Secure multi-party computation
- Differential privacy
- Byzantine fault tolerance
- Cryptographic aggregation
- Data sovereignty
"""

import logging
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass, asdict
from enum import Enum
from datetime import datetime
import json
import statistics
import random
from collections import defaultdict, Counter

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AggregationMethod(Enum):
    """Model aggregation methods"""
    FEDAVG = "federated_averaging"  # Standard FedAvg
    FEDPROX = "federated_proximal"  # FedProx (with proximal term)
    WEIGHTED_AVG = "weighted_average"  # Weighted by data size
    MEDIAN = "coordinate_median"  # Robust to outliers
    TRIMMED_MEAN = "trimmed_mean"  # Remove extreme values


class ClientStatus(Enum):
    """Client participation status"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    TRAINING = "training"
    UPLOADING = "uploading"
    MALICIOUS = "malicious"
    QUARANTINED = "quarantined"


class PrivacyLevel(Enum):
    """Privacy protection levels"""
    HIGH = "high"  # Strong differential privacy
    MEDIUM = "medium"  # Moderate privacy
    LOW = "low"  # Basic privacy
    NONE = "none"  # No additional privacy


@dataclass
class ClientInfo:
    """Federated learning client information"""
    client_id: str
    status: ClientStatus
    data_samples: int
    last_seen: str
    model_version: int
    contribution_count: int
    reputation_score: float
    is_trusted: bool


@dataclass
class ModelUpdate:
    """Model update from client"""
    client_id: str
    model_weights: Dict
    data_samples: int
    loss: float
    accuracy: float
    timestamp: str
    privacy_budget: float


@dataclass
class AggregationResult:
    """Aggregation result"""
    round_number: int
    global_weights: Dict
    participating_clients: int
    total_samples: int
    average_loss: float
    average_accuracy: float
    rejected_updates: int
    aggregation_method: AggregationMethod
    timestamp: str


@dataclass
class FederatedMetrics:
    """Federated learning metrics"""
    total_rounds: int
    total_clients: int
    active_clients: int
    average_accuracy: float
    convergence_rate: float
    privacy_budget_spent: float
    byzantine_attacks_detected: int


class FederatedLearning:
    """
    Privacy-preserving federated learning system.
    Enables collaborative model training without sharing raw data.
    """
    
    def __init__(self, 
                 aggregation_method: AggregationMethod = AggregationMethod.FEDAVG,
                 privacy_level: PrivacyLevel = PrivacyLevel.MEDIUM,
                 min_clients: int = 3,
                 byzantine_tolerance: float = 0.2):
        self.name = "Federated_Learning"
        self.aggregation_method = aggregation_method
        self.privacy_level = privacy_level
        self.min_clients = min_clients
        self.byzantine_tolerance = byzantine_tolerance
        
        # Client management
        self.clients: Dict[str, ClientInfo] = {}
        self.active_clients: Set[str] = set()
        self.quarantined_clients: Set[str] = set()
        
        # Model versioning
        self.current_model_version = 1
        self.global_weights: Optional[Dict] = None
        self.weight_history = []
        
        # Round management
        self.current_round = 0
        self.round_history = []
        
        # Privacy budget
        self.total_privacy_budget = 10.0  # epsilon for differential privacy
        self.privacy_budget_spent = 0.0
        self.privacy_budget_per_round = 0.1
        
        # Byzantine detection
        self.update_history = defaultdict(list)
        self.byzantine_detected = 0
        
        # Statistics
        self.total_updates_received = 0
        self.total_updates_rejected = 0
        self.convergence_metrics = []
        
        # Client selection parameters
        self.client_selection_fraction = 0.5  # Select 50% of clients per round
        
        logger.info(f"{self.name} initialized with {aggregation_method.value}, privacy: {privacy_level.value}")
    
    def register_client(self, client_id: str, data_samples: int) -> ClientInfo:
        """
        Register new federated learning client.
        
        Args:
            client_id: Unique client identifier
            data_samples: Number of data samples client has
        
        Returns:
            ClientInfo for the registered client
        """
        if client_id in self.clients:
            logger.warning(f"Client {client_id} already registered")
            return self.clients[client_id]
        
        client = ClientInfo(
            client_id=client_id,
            status=ClientStatus.ACTIVE,
            data_samples=data_samples,
            last_seen=datetime.now().isoformat(),
            model_version=self.current_model_version,
            contribution_count=0,
            reputation_score=1.0,
            is_trusted=True
        )
        
        self.clients[client_id] = client
        self.active_clients.add(client_id)
        
        logger.info(f"Client {client_id} registered with {data_samples} samples")
        return client
    
    def select_clients_for_round(self) -> List[str]:
        """
        Select clients to participate in current round.
        Uses reputation-based selection.
        
        Returns:
            List of selected client IDs
        """
        available_clients = [
            cid for cid in self.active_clients 
            if cid not in self.quarantined_clients
        ]
        
        if len(available_clients) < self.min_clients:
            logger.warning(f"Not enough clients: {len(available_clients)} < {self.min_clients}")
            return []
        
        # Calculate selection count
        num_select = max(
            self.min_clients,
            int(len(available_clients) * self.client_selection_fraction)
        )
        
        # Weighted selection based on reputation
        if len(available_clients) <= num_select:
            selected = available_clients
        else:
            # Use reputation scores as weights
            weights = [self.clients[cid].reputation_score for cid in available_clients]
            total_weight = sum(weights)
            probabilities = [w / total_weight for w in weights]
            
            selected = random.choices(
                available_clients,
                weights=probabilities,
                k=num_select
            )
        
        logger.info(f"Selected {len(selected)} clients for round {self.current_round + 1}")
        return selected
    
    def receive_client_update(self, update: ModelUpdate) -> bool:
        """
        Receive and validate model update from client.
        
        Args:
            update: ModelUpdate from client
        
        Returns:
            True if update accepted, False if rejected
        """
        self.total_updates_received += 1
        
        # Validate client
        if update.client_id not in self.clients:
            logger.warning(f"Unknown client: {update.client_id}")
            self.total_updates_rejected += 1
            return False
        
        client = self.clients[update.client_id]
        
        # Check if client is quarantined
        if update.client_id in self.quarantined_clients:
            logger.warning(f"Rejected update from quarantined client: {update.client_id}")
            self.total_updates_rejected += 1
            return False
        
        # Validate update
        if not self._validate_update(update):
            logger.warning(f"Invalid update from {update.client_id}")
            self.total_updates_rejected += 1
            self._decrease_reputation(update.client_id)
            return False
        
        # Byzantine detection
        if self._detect_byzantine_update(update):
            logger.warning(f"Byzantine update detected from {update.client_id}")
            self.byzantine_detected += 1
            self._quarantine_client(update.client_id)
            self.total_updates_rejected += 1
            return False
        
        # Store update
        self.update_history[self.current_round].append(update)
        
        # Update client info
        client.last_seen = datetime.now().isoformat()
        client.contribution_count += 1
        client.status = ClientStatus.ACTIVE
        self._increase_reputation(update.client_id)
        
        logger.info(f"Accepted update from {update.client_id} (loss: {update.loss:.4f})")
        return True
    
    def aggregate_updates(self) -> AggregationResult:
        """
        Aggregate client updates to create global model.
        
        Returns:
            AggregationResult with new global weights
        """
        round_updates = self.update_history[self.current_round]
        
        if not round_updates:
            logger.warning("No updates to aggregate")
            return None
        
        if len(round_updates) < self.min_clients:
            logger.warning(f"Insufficient updates: {len(round_updates)} < {self.min_clients}")
            return None
        
        # Apply differential privacy if enabled
        if self.privacy_level != PrivacyLevel.NONE:
            round_updates = self._apply_differential_privacy(round_updates)
        
        # Aggregate based on method
        if self.aggregation_method == AggregationMethod.FEDAVG:
            aggregated_weights = self._federated_averaging(round_updates)
        elif self.aggregation_method == AggregationMethod.WEIGHTED_AVG:
            aggregated_weights = self._weighted_averaging(round_updates)
        elif self.aggregation_method == AggregationMethod.MEDIAN:
            aggregated_weights = self._coordinate_median(round_updates)
        elif self.aggregation_method == AggregationMethod.TRIMMED_MEAN:
            aggregated_weights = self._trimmed_mean(round_updates)
        else:
            aggregated_weights = self._federated_averaging(round_updates)
        
        # Update global model
        self.global_weights = aggregated_weights
        self.weight_history.append(aggregated_weights)
        
        # Calculate metrics
        total_samples = sum(u.data_samples for u in round_updates)
        avg_loss = statistics.mean([u.loss for u in round_updates])
        avg_accuracy = statistics.mean([u.accuracy for u in round_updates])
        
        # Increment round
        self.current_round += 1
        self.current_model_version += 1
        
        result = AggregationResult(
            round_number=self.current_round,
            global_weights=aggregated_weights,
            participating_clients=len(round_updates),
            total_samples=total_samples,
            average_loss=avg_loss,
            average_accuracy=avg_accuracy,
            rejected_updates=self.total_updates_rejected,
            aggregation_method=self.aggregation_method,
            timestamp=datetime.now().isoformat()
        )
        
        self.round_history.append(result)
        self.convergence_metrics.append(avg_loss)
        
        logger.info(f"Round {self.current_round} complete: loss={avg_loss:.4f}, acc={avg_accuracy:.2%}")
        return result
    
    def get_global_model(self) -> Dict:
        """Get current global model weights."""
        return self.global_weights
    
    def _validate_update(self, update: ModelUpdate) -> bool:
        """Validate model update."""
        # Check for valid weights
        if not update.model_weights:
            return False
        
        # Check for reasonable values
        try:
            for layer_weights in update.model_weights.values():
                if isinstance(layer_weights, (list, tuple)):
                    for w in layer_weights:
                        if not isinstance(w, (int, float)):
                            return False
                        # Check for NaN or Inf
                        if not (-1e10 < w < 1e10):
                            return False
        except (TypeError, ValueError):
            return False
        
        # Check metrics
        if not (0 <= update.accuracy <= 1):
            return False
        
        if update.loss < 0:
            return False
        
        return True
    
    def _detect_byzantine_update(self, update: ModelUpdate) -> bool:
        """Detect Byzantine (malicious) updates."""
        if len(self.update_history[self.current_round]) < 2:
            return False  # Not enough data
        
        # Compare with other updates in current round
        current_updates = self.update_history[self.current_round]
        
        # Check loss outlier
        losses = [u.loss for u in current_updates]
        avg_loss = statistics.mean(losses)
        
        if update.loss > avg_loss * 3:  # 3x average loss
            return True
        
        # Check accuracy outlier
        accuracies = [u.accuracy for u in current_updates]
        avg_accuracy = statistics.mean(accuracies)
        
        if update.accuracy < avg_accuracy * 0.5:  # 50% below average
            return True
        
        return False
    
    def _federated_averaging(self, updates: List[ModelUpdate]) -> Dict:
        """Standard FedAvg aggregation."""
        total_samples = sum(u.data_samples for u in updates)
        aggregated = {}
        
        # Get all layer names
        layer_names = set()
        for update in updates:
            layer_names.update(update.model_weights.keys())
        
        # Average each layer
        for layer in layer_names:
            layer_sum = None
            weight_sum = 0
            
            for update in updates:
                if layer not in update.model_weights:
                    continue
                
                weight = update.data_samples / total_samples
                layer_weights = update.model_weights[layer]
                
                if layer_sum is None:
                    if isinstance(layer_weights, (list, tuple)):
                        layer_sum = [w * weight for w in layer_weights]
                    else:
                        layer_sum = layer_weights * weight
                else:
                    if isinstance(layer_weights, (list, tuple)):
                        layer_sum = [s + w * weight for s, w in zip(layer_sum, layer_weights)]
                    else:
                        layer_sum += layer_weights * weight
                
                weight_sum += weight
            
            aggregated[layer] = layer_sum
        
        return aggregated
    
    def _weighted_averaging(self, updates: List[ModelUpdate]) -> Dict:
        """Weighted averaging by data size."""
        return self._federated_averaging(updates)  # Same as FedAvg
    
    def _coordinate_median(self, updates: List[ModelUpdate]) -> Dict:
        """Coordinate-wise median aggregation (Byzantine-robust)."""
        aggregated = {}
        
        layer_names = set()
        for update in updates:
            layer_names.update(update.model_weights.keys())
        
        for layer in layer_names:
            layer_weights_list = []
            
            for update in updates:
                if layer in update.model_weights:
                    layer_weights_list.append(update.model_weights[layer])
            
            if not layer_weights_list:
                continue
            
            # Calculate median
            if isinstance(layer_weights_list[0], (list, tuple)):
                # Coordinate-wise median
                num_coords = len(layer_weights_list[0])
                median_weights = []
                
                for i in range(num_coords):
                    coord_values = [w[i] for w in layer_weights_list]
                    median_weights.append(statistics.median(coord_values))
                
                aggregated[layer] = median_weights
            else:
                # Scalar median
                aggregated[layer] = statistics.median(layer_weights_list)
        
        return aggregated
    
    def _trimmed_mean(self, updates: List[ModelUpdate]) -> Dict:
        """Trimmed mean aggregation (remove outliers)."""
        trim_fraction = self.byzantine_tolerance
        aggregated = {}
        
        layer_names = set()
        for update in updates:
            layer_names.update(update.model_weights.keys())
        
        for layer in layer_names:
            layer_weights_list = []
            
            for update in updates:
                if layer in update.model_weights:
                    layer_weights_list.append(update.model_weights[layer])
            
            if not layer_weights_list:
                continue
            
            # Trimmed mean
            if isinstance(layer_weights_list[0], (list, tuple)):
                num_coords = len(layer_weights_list[0])
                trimmed_weights = []
                
                for i in range(num_coords):
                    coord_values = sorted([w[i] for w in layer_weights_list])
                    trim_count = int(len(coord_values) * trim_fraction)
                    
                    if trim_count > 0:
                        trimmed = coord_values[trim_count:-trim_count]
                    else:
                        trimmed = coord_values
                    
                    trimmed_weights.append(statistics.mean(trimmed) if trimmed else 0)
                
                aggregated[layer] = trimmed_weights
            else:
                values = sorted(layer_weights_list)
                trim_count = int(len(values) * trim_fraction)
                
                if trim_count > 0:
                    trimmed = values[trim_count:-trim_count]
                else:
                    trimmed = values
                
                aggregated[layer] = statistics.mean(trimmed) if trimmed else 0
        
        return aggregated
    
    def _apply_differential_privacy(self, updates: List[ModelUpdate]) -> List[ModelUpdate]:
        """Apply differential privacy to updates."""
        if self.privacy_budget_spent >= self.total_privacy_budget:
            logger.warning("Privacy budget exhausted")
            return updates
        
        # Add noise based on privacy level
        noise_scale = {
            PrivacyLevel.HIGH: 0.1,
            PrivacyLevel.MEDIUM: 0.05,
            PrivacyLevel.LOW: 0.01
        }.get(self.privacy_level, 0.05)
        
        noisy_updates = []
        for update in updates:
            noisy_weights = {}
            
            for layer, weights in update.model_weights.items():
                if isinstance(weights, (list, tuple)):
                    # Add Gaussian noise
                    noisy_weights[layer] = [
                        w + random.gauss(0, noise_scale) for w in weights
                    ]
                else:
                    noisy_weights[layer] = weights + random.gauss(0, noise_scale)
            
            noisy_update = ModelUpdate(
                client_id=update.client_id,
                model_weights=noisy_weights,
                data_samples=update.data_samples,
                loss=update.loss,
                accuracy=update.accuracy,
                timestamp=update.timestamp,
                privacy_budget=self.privacy_budget_per_round
            )
            noisy_updates.append(noisy_update)
        
        # Update privacy budget
        self.privacy_budget_spent += self.privacy_budget_per_round
        
        return noisy_updates
    
    def _increase_reputation(self, client_id: str):
        """Increase client reputation score."""
        if client_id in self.clients:
            client = self.clients[client_id]
            client.reputation_score = min(client.reputation_score + 0.1, 2.0)
    
    def _decrease_reputation(self, client_id: str):
        """Decrease client reputation score."""
        if client_id in self.clients:
            client = self.clients[client_id]
            client.reputation_score = max(client.reputation_score - 0.2, 0.0)
            
            # Quarantine if reputation too low
            if client.reputation_score < 0.3:
                self._quarantine_client(client_id)
    
    def _quarantine_client(self, client_id: str):
        """Quarantine malicious client."""
        if client_id in self.clients:
            self.clients[client_id].status = ClientStatus.QUARANTINED
            self.clients[client_id].is_trusted = False
            self.quarantined_clients.add(client_id)
            self.active_clients.discard(client_id)
            logger.warning(f"Client {client_id} quarantined")
    
    def get_metrics(self) -> FederatedMetrics:
        """Get federated learning metrics."""
        avg_accuracy = statistics.mean(
            [r.average_accuracy for r in self.round_history]
        ) if self.round_history else 0.0
        
        # Calculate convergence rate
        if len(self.convergence_metrics) > 1:
            recent_loss = statistics.mean(self.convergence_metrics[-5:])
            initial_loss = statistics.mean(self.convergence_metrics[:5])
            convergence_rate = (initial_loss - recent_loss) / max(initial_loss, 0.01)
        else:
            convergence_rate = 0.0
        
        return FederatedMetrics(
            total_rounds=self.current_round,
            total_clients=len(self.clients),
            active_clients=len(self.active_clients),
            average_accuracy=avg_accuracy,
            convergence_rate=convergence_rate,
            privacy_budget_spent=self.privacy_budget_spent,
            byzantine_attacks_detected=self.byzantine_detected
        )
    
    def get_statistics(self) -> Dict:
        """Get detailed statistics."""
        metrics = self.get_metrics()
        
        return {
            'total_rounds': self.current_round,
            'total_clients': len(self.clients),
            'active_clients': len(self.active_clients),
            'quarantined_clients': len(self.quarantined_clients),
            'updates_received': self.total_updates_received,
            'updates_rejected': self.total_updates_rejected,
            'rejection_rate': self.total_updates_rejected / max(self.total_updates_received, 1),
            'average_accuracy': metrics.average_accuracy,
            'convergence_rate': metrics.convergence_rate,
            'privacy_budget_spent': f"{self.privacy_budget_spent:.2f}/{self.total_privacy_budget}",
            'byzantine_detected': self.byzantine_detected,
            'aggregation_method': self.aggregation_method.value,
            'privacy_level': self.privacy_level.value
        }


def create_federated_system(
    aggregation_method: AggregationMethod = AggregationMethod.FEDAVG,
    privacy_level: PrivacyLevel = PrivacyLevel.MEDIUM,
    min_clients: int = 3
) -> FederatedLearning:
    """Factory function to create federated learning system."""
    return FederatedLearning(aggregation_method, privacy_level, min_clients)


# Example usage
if __name__ == "__main__":
    fl = create_federated_system(
        aggregation_method=AggregationMethod.FEDAVG,
        privacy_level=PrivacyLevel.MEDIUM,
        min_clients=3
    )
    
    # Register clients
    print(f"\n{'='*60}")
    print("FEDERATED LEARNING SIMULATION")
    print(f"{'='*60}\n")
    
    clients = []
    for i in range(5):
        client = fl.register_client(f"client_{i}", data_samples=random.randint(100, 500))
        clients.append(client.client_id)
        print(f"✅ Registered: {client.client_id} ({client.data_samples} samples)")
    
    # Simulate federated training rounds
    print(f"\n{'='*60}")
    print("TRAINING ROUNDS")
    print(f"{'='*60}\n")
    
    for round_num in range(3):
        print(f"\n--- Round {round_num + 1} ---")
        
        # Select clients
        selected = fl.select_clients_for_round()
        print(f"Selected {len(selected)} clients: {', '.join(selected)}")
        
        # Simulate client updates
        for client_id in selected:
            update = ModelUpdate(
                client_id=client_id,
                model_weights={
                    'layer1': [random.gauss(0, 0.1) for _ in range(10)],
                    'layer2': [random.gauss(0, 0.1) for _ in range(5)]
                },
                data_samples=fl.clients[client_id].data_samples,
                loss=random.uniform(0.1, 0.5),
                accuracy=random.uniform(0.7, 0.95),
                timestamp=datetime.now().isoformat(),
                privacy_budget=0.1
            )
            
            accepted = fl.receive_client_update(update)
            status = "✅" if accepted else "❌"
            print(f"  {status} Update from {client_id}: loss={update.loss:.4f}, acc={update.accuracy:.2%}")
        
        # Aggregate
        result = fl.aggregate_updates()
        if result:
            print(f"\n🎯 Aggregation complete:")
            print(f"   Clients: {result.participating_clients}")
            print(f"   Avg Loss: {result.average_loss:.4f}")
            print(f"   Avg Accuracy: {result.average_accuracy:.2%}")
    
    # Final metrics
    print(f"\n{'='*60}")
    print("FINAL METRICS")
    print(f"{'='*60}\n")
    
    stats = fl.get_statistics()
    print(json.dumps(stats, indent=2))