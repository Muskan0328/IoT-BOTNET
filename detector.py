"""
IoT Botnet Detection System - Complete Working Version
DDoS, Reconnaissance, and C&C Attack Detection
With Demo Buttons for Presentation
"""

import time
import threading
import psutil
from datetime import datetime
from collections import deque

class NetworkMonitor:
    def __init__(self):
        # Traffic data
        self.current_pps = 0
        self.traffic_history = deque(maxlen=30)
        
        # REAL Attack state
        self.real_attack_active = False
        self.real_attack_type = None
        self.real_attack_end_time = 0
        
        # DEMO Attack state (for buttons)
        self.demo_attack_active = False
        self.demo_attack_type = None
        self.demo_attack_end_time = 0
        
        # Statistics
        self.total_packets = 0
        self.normal_packets = 0
        self.attack_packets = 0
        self.attack_counts = {
            'ddos': 0,
            'recon': 0,
            'cc': 0
        }
        
        # Alerts storage
        self.alerts = []
        
        # Cooldown between different attack events
        self.last_alert_time = 0
        self.alert_cooldown = 25
        
        # Baseline
        self.baseline_pps = 40
        self.baseline_samples = []
        self.baseline_ready = False
        
        self.running = True
        
    def start_monitoring(self):
        print("\n" + "="*60)
        print("IoT BOTNET DETECTION SYSTEM")
        print("="*60)
        print("Detecting: DDoS | Reconnaissance | C&C Attacks")
        print("Demo buttons available for presentation")
        print("="*60 + "\n")
        
        self.calculate_baseline()
        
        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
    
    def calculate_baseline(self):
        """Learn what normal traffic looks like on YOUR computer"""
        print("Analyzing your normal traffic pattern...")
        print("Please wait 15 seconds.\n")
        
        samples = []
        for i in range(15):
            bytes1 = psutil.net_io_counters().bytes_recv + psutil.net_io_counters().bytes_sent
            time.sleep(1)
            bytes2 = psutil.net_io_counters().bytes_recv + psutil.net_io_counters().bytes_sent
            bytes_diff = bytes2 - bytes1
            pps = int(bytes_diff / 1500) if bytes_diff > 0 else 0
            samples.append(pps)
            print(f"Sample {i+1:2d}: {pps:3d} packets/sec", end="\r")
        
        avg_pps = int(sum(samples) / len(samples))
        max_pps = max(samples)
        
        self.baseline_pps = max(max_pps + 15, avg_pps + 10, 35)
        
        print(f"\n\nBaseline established: {self.baseline_pps} packets/second")
        print(f"   Your average: {avg_pps} pps | Peak: {max_pps} pps")
        print(f"\nAttack thresholds:")
        print(f"   DDoS: > {self.baseline_pps * 3} pps")
        print(f"   Reconnaissance: > {self.baseline_pps * 2} pps")
        print(f"   C&C: > {self.baseline_pps * 1.8} pps (sustained)\n")
        self.baseline_ready = True
    
    def _monitor_loop(self):
        last_recv = psutil.net_io_counters().bytes_recv
        last_sent = psutil.net_io_counters().bytes_sent
        last_time = time.time()
        
        while self.running:
            current_recv = psutil.net_io_counters().bytes_recv
            current_sent = psutil.net_io_counters().bytes_sent
            current_time = time.time()
            
            time_diff = current_time - last_time
            if time_diff > 0:
                bytes_recv_sec = (current_recv - last_recv) / time_diff
                bytes_sent_sec = (current_sent - last_sent) / time_diff
                total_bytes_sec = bytes_recv_sec + bytes_sent_sec
                self.current_pps = int(total_bytes_sec / 1500) if total_bytes_sec > 0 else 0
            else:
                self.current_pps = 0
            
            self.total_packets += self.current_pps
            
            # Check if attacks should end
            if self.real_attack_active and current_time > self.real_attack_end_time:
                self.real_attack_active = False
                self.real_attack_type = None
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Real attack ended")
            
            if self.demo_attack_active and current_time > self.demo_attack_end_time:
                self.demo_attack_active = False
                self.demo_attack_type = None
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Demo attack ended")
            
            # Determine if any attack is active
            is_attack_active = self.real_attack_active or self.demo_attack_active
            
            # Update counters
            if is_attack_active:
                self.attack_packets += self.current_pps
            else:
                self.normal_packets += self.current_pps
            
            timestamp = datetime.now().strftime('%H:%M:%S')
            self.traffic_history.append({
                'time': timestamp,
                'pps': self.current_pps,
                'attack': is_attack_active
            })
            
            while len(self.traffic_history) > 30:
                self.traffic_history.popleft()
            
            # DETECT REAL ATTACKS - only if no demo attack active
            if not self.demo_attack_active and not self.real_attack_active:
                self.detect_real_attack()
            
            # Print status every 10 seconds
            if int(time.time()) % 10 == 0:
                if self.real_attack_active:
                    print(f"[{timestamp}] REAL ATTACK: {self.real_attack_type.upper()} | {self.current_pps} pps")
                elif self.demo_attack_active:
                    print(f"[{timestamp}] DEMO ATTACK: {self.demo_attack_type.upper()} | {self.current_pps} pps")
                else:
                    print(f"[{timestamp}] NORMAL: {self.current_pps} pps (Baseline: {self.baseline_pps})")
            
            last_recv = current_recv
            last_sent = current_sent
            last_time = current_time
            time.sleep(1)
    
    def detect_real_attack(self):
        """Detect REAL attacks - called only when no attack active"""
        if not self.baseline_ready:
            return
        
        current_time = time.time()
        
        # Cooldown between different attack events
        if current_time - self.last_alert_time < self.alert_cooldown:
            return
        
        ratio = self.current_pps / self.baseline_pps if self.baseline_pps > 0 else 1
        
        # DDoS Detection: Very high traffic spike
        if ratio > 3.0 and self.current_pps > 150:
            self.trigger_real_attack('ddos', ratio)
            self.last_alert_time = current_time
            self.real_attack_end_time = current_time + 10
        
        # Reconnaissance Detection: Moderate spike
        elif ratio > 2.0 and self.current_pps > 80:
            self.trigger_real_attack('recon', ratio)
            self.last_alert_time = current_time
            self.real_attack_end_time = current_time + 8
        
        # C&C Detection: Persistent moderate traffic
        elif ratio > 1.8 and self.current_pps > 60:
            if len(self.traffic_history) >= 5:
                recent_pps = [t['pps'] for t in list(self.traffic_history)[-5:]]
                avg_recent = sum(recent_pps) / len(recent_pps)
                if avg_recent > self.baseline_pps * 1.5:
                    self.trigger_real_attack('cc', ratio)
                    self.last_alert_time = current_time
                    self.real_attack_end_time = current_time + 10
    
    def trigger_real_attack(self, attack_type, ratio):
        """Trigger a REAL attack alert"""
        if self.real_attack_active or self.demo_attack_active:
            return
        
        self.real_attack_active = True
        self.real_attack_type = attack_type
        self.attack_counts[attack_type] += 1
        
        confidence = min(0.98, 0.75 + (ratio / 25))
        
        attack_messages = {
            'ddos': 'DDoS Attack: Massive traffic flood detected on your network',
            'recon': 'Reconnaissance Attack: System scanning detected - possible port scan',
            'cc': 'C&C Attack: Suspicious external communication detected - possible malware beacon'
        }
        
        alert = {
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'type': attack_type,
            'message': attack_messages.get(attack_type, f'{attack_type.upper()} attack detected'),
            'confidence': confidence,
            'source': 'REAL TRAFFIC',
            'details': f'Traffic: {self.current_pps} pps (Normal: {self.baseline_pps} pps)'
        }
        self.alerts.insert(0, alert)
        
        print(f"\n{'='*55}")
        print(f"🔴 REAL ATTACK DETECTED: {attack_type.upper()}")
        print(f"   Traffic: {self.current_pps} pps | Normal: {self.baseline_pps} pps")
        print(f"   Ratio: {ratio:.1f}x | Confidence: {confidence:.1%}")
        print(f"{'='*55}\n")
    
    def start_demo_attack(self, attack_type):
        """Start a DEMO attack for professor presentation"""
        if self.real_attack_active or self.demo_attack_active:
            return
        
        self.demo_attack_active = True
        self.demo_attack_type = attack_type
        self.attack_counts[attack_type] += 1
        self.demo_attack_end_time = time.time() + 10
        
        confidence = 0.95
        
        attack_messages = {
            'ddos': 'DDoS Attack Simulation: Massive traffic flood (Demo for presentation)',
            'recon': 'Reconnaissance Attack Simulation: Port scanning activity (Demo for presentation)',
            'cc': 'C&C Attack Simulation: Malware beacon detected (Demo for presentation)'
        }
        
        alert = {
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'type': attack_type,
            'message': attack_messages.get(attack_type, f'{attack_type.upper()} attack simulation'),
            'confidence': confidence,
            'source': 'DEMO BUTTON',
            'details': 'Presentation demonstration - No actual network harm'
        }
        self.alerts.insert(0, alert)
        
        print(f"\n{'='*55}")
        print(f"🟠 DEMO ATTACK: {attack_type.upper()} (For Presentation)")
        print(f"   Will auto-stop in 10 seconds")
        print(f"{'='*55}\n")
    
    def stop_demo_attack(self):
        """Stop the DEMO attack"""
        self.demo_attack_active = False
        self.demo_attack_type = None
        print(f"\nDemo attack stopped\n")
    
    def get_statistics(self):
        total = self.total_packets
        is_attack = self.real_attack_active or self.demo_attack_active
        
        if total > 0:
            normal_percent = (self.normal_packets / total * 100)
            attack_percent = (self.attack_packets / total * 100)
        else:
            normal_percent = 100
            attack_percent = 0
        
        # Determine active attack type for display
        active_type = None
        if self.real_attack_active:
            active_type = self.real_attack_type
        elif self.demo_attack_active:
            active_type = self.demo_attack_type
        
        return {
            'total_packets': self.total_packets,
            'normal_percent': round(normal_percent, 1),
            'attack_percent': round(attack_percent, 1),
            'ddos_count': self.attack_counts['ddos'],
            'recon_count': self.attack_counts['recon'],
            'cc_count': self.attack_counts['cc'],
            'attack_active': is_attack,
            'attack_type': active_type,
            'attack_source': 'REAL' if self.real_attack_active else ('DEMO' if self.demo_attack_active else None),
            'current_pps': self.current_pps,
            'baseline_pps': self.baseline_pps,
            'traffic_history': list(self.traffic_history),
            'alerts': self.alerts[:30]
        }