import time
import sys
import queue
import logging
import os
import json
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QTabWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QTableWidget, QTableWidgetItem, QHeaderView, QPushButton, QLabel,
    QComboBox, QSpinBox, QCheckBox, QLineEdit, QListWidget, QMessageBox, QGroupBox, QFormLayout
)
from PyQt6.QtCore import QTimer, Qt
from PyQt6.QtGui import QColor, QFont
from netcat.gui.charts import ChartsWidget
from netcat.dpi import AppType, sni_to_app_type, DPIEngine
from netcat.capture import list_interfaces

class DashboardWindow(QMainWindow):
    def __init__(self, config_manager, db_manager, block_manager, alert_queue, stats_queue, traffic_queue, packet_queue=None):
        super().__init__()
        self.config = config_manager
        self.db = db_manager
        self.block_manager = block_manager
        self.alert_queue = alert_queue
        self.stats_queue = stats_queue
        self.traffic_queue = traffic_queue
        self.packet_queue = packet_queue
        
        # Thread references
        self.capture_thread = None
        self.detector_thread = None

        self.setWindowTitle("netcat — Network Threat Monitoring & Blocking Dashboard")
        self.resize(1100, 750)
        
        # Dark Theme Styling
        self.setStyleSheet("""
            QMainWindow {
                background-color: #12121f;
            }
            QWidget {
                background-color: #12121f;
                color: #d1d1eb;
                font-family: 'Segoe UI', Arial, sans-serif;
                font-size: 13px;
            }
            QTabWidget::pane {
                border: 1px solid #1a1a2e;
                background-color: #16162a;
                border-radius: 8px;
            }
            QTabBar::tab {
                background-color: #1a1a32;
                border: 1px solid #1a1a2e;
                padding: 10px 20px;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                margin-right: 4px;
                font-weight: bold;
            }
            QTabBar::tab:selected {
                background-color: #16162a;
                border-bottom: 2px solid #00f3ff;
                color: #00f3ff;
            }
            QTableWidget {
                background-color: #16162a;
                alternate-background-color: #1d1d36;
                gridline-color: #1a1a32;
                border: 1px solid #1a1a32;
                border-radius: 4px;
            }
            QHeaderView::section {
                background-color: #1a1a32;
                color: #00f3ff;
                padding: 6px;
                border: 1px solid #12121f;
                font-weight: bold;
            }
            QPushButton {
                background-color: #1e1e3f;
                border: 1px solid #333366;
                padding: 6px 12px;
                border-radius: 4px;
                color: #d1d1eb;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #00f3ff;
                color: #12121f;
                border: 1px solid #00f3ff;
            }
            QPushButton:pressed {
                background-color: #00b3cc;
            }
            QGroupBox {
                border: 1px solid #1a1a32;
                border-radius: 6px;
                margin-top: 12px;
                font-weight: bold;
                color: #00f3ff;
                padding: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 3px 0 3px;
            }
            QLineEdit, QSpinBox, QComboBox {
                background-color: #16162a;
                border: 1px solid #1a1a32;
                border-radius: 4px;
                padding: 4px;
                color: #d1d1eb;
            }
            QLineEdit:focus, QSpinBox:focus, QComboBox:focus {
                border: 1px solid #00f3ff;
            }
            QCheckBox {
                spacing: 8px;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
                background-color: #16162a;
                border: 1px solid #1a1a32;
                border-radius: 3px;
            }
            QCheckBox::indicator:checked {
                background-color: #00f3ff;
                image: url(checked.png); /* Fallback to styled colors */
            }
            QListWidget {
                background-color: #16162a;
                border: 1px solid #1a1a32;
                border-radius: 4px;
            }
        """)

        # Main Central Widget
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)
        
        # Header Layout
        self.setup_header()
        
        # Tab Widgets
        self.tabs = QTabWidget()
        self.main_layout.addWidget(self.tabs)
        
        self.setup_live_traffic_tab()
        self.setup_threats_tab()
        self.setup_blocked_ips_tab()
        self.setup_charts_tab()
        self.setup_settings_tab()
        
        # Bottom Status Banner showing selected interface and providing change action
        self.setup_status_banner()
        
        # Initialize UI state from config
        self.refresh_blocked_table()
        
        # Polling Timer for GUI Queue updates
        self.ui_timer = QTimer(self)
        self.ui_timer.setInterval(100)  # 100ms
        self.ui_timer.timeout.connect(self.poll_queues)
        self.ui_timer.start()

    def setup_header(self):
        header_layout = QHBoxLayout()
        self.main_layout.addLayout(header_layout)
        
        # Title container with icon
        title_box = QHBoxLayout()
        header_layout.addLayout(title_box)
        
        logo_label = QLabel()
        from PyQt6.QtGui import QPixmap
        logo_pix = QPixmap("netcat_logo.png")
        if not logo_pix.isNull():
            logo_label.setPixmap(logo_pix.scaled(32, 32, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation))
            title_box.addWidget(logo_label)
            
        self.title_label = QLabel("netcat")
        title_font = QFont("Segoe UI", 18, QFont.Weight.Bold)
        self.title_label.setFont(title_font)
        self.title_label.setStyleSheet("color: #00f3ff; letter-spacing: 2px;")
        title_box.addWidget(self.title_label)
        
        header_layout.addStretch()
        
        self.protection_btn = QPushButton()
        self.protection_btn.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        self.protection_btn.clicked.connect(self.toggle_protection_status)
        self.update_safe_mode_header()
        header_layout.addWidget(self.protection_btn)

        # Space separator
        header_layout.addSpacing(10)

        # Shutdown button
        self.shutdown_btn = QPushButton("Shutdown netcat")
        self.shutdown_btn.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        self.shutdown_btn.setStyleSheet("""
            QPushButton {
                background-color: #3f1e1e;
                border: 1px solid #663333;
                color: #ebcdcd;
                padding: 8px 16px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #8c2626;
                color: #ffffff;
                border: 1px solid #cc4444;
            }
        """)
        self.shutdown_btn.clicked.connect(self.graceful_shutdown)
        header_layout.addWidget(self.shutdown_btn)

    def update_safe_mode_header(self):
        is_safe = self.config.get("safe_mode", True)
        if is_safe:
            self.protection_btn.setText("⚠️ Safe Mode: ON (BLOCKING DISABLED)")
            self.protection_btn.setStyleSheet("""
                QPushButton {
                    color: #ff9f43; 
                    background-color: #291a0c; 
                    padding: 8px 16px; 
                    border-radius: 4px; 
                    border: 1px solid #ff9f43;
                    font-weight: bold;
                }
                QPushButton:hover {
                    background-color: #ff9f43;
                    color: #12121f;
                }
            """)
        else:
            self.protection_btn.setText("🛡️ Protection: ON (AUTO-BLOCKING ACTIVE)")
            self.protection_btn.setStyleSheet("""
                QPushButton {
                    color: #00f3ff; 
                    background-color: #0c2929; 
                    padding: 8px 16px; 
                    border-radius: 4px; 
                    border: 1px solid #00f3ff;
                    font-weight: bold;
                }
                QPushButton:hover {
                    background-color: #00f3ff;
                    color: #12121f;
                }
            """)

    def toggle_protection_status(self):
        is_safe = self.config.get("safe_mode", True)
        new_safe = not is_safe
        self.config.set("safe_mode", new_safe)
        self.update_safe_mode_header()
        
        # Sync the checkbox in the settings tab if it exists
        if hasattr(self, 'safe_mode_checkbox'):
            self.safe_mode_checkbox.blockSignals(True)
            self.safe_mode_checkbox.setChecked(new_safe)
            self.safe_mode_checkbox.blockSignals(False)
            
        # If toggled to Safe Mode (new_safe is True), unblock all active blocks for safety!
        if new_safe:
            self.block_manager.clean_all_blocks()
            self.refresh_blocked_table()
            QMessageBox.information(self, "Safe Mode Enabled", "Auto-blocking has been disabled. All active firewall and WinDivert blocks have been safely cleared.")
        else:
            QMessageBox.information(self, "Protection Enabled", "Auto-blocking is now active. Any detected threats exceeding severity threshold will be blocked in real-time.")

    def graceful_shutdown(self):
        logging.info("netcat shutting down (user-initiated)")
        
        # 1. Stop capture thread
        if self.capture_thread:
            try:
                self.capture_thread.stop()
            except Exception:
                pass
            
        # 2. Stop detector thread
        if self.detector_thread:
            try:
                self.detector_thread.stop()
            except Exception:
                pass
            
        # 3. Shutdown blocker cleanly (stops WinDivert, persists firewall rules)
        if self.block_manager:
            try:
                self.block_manager.shutdown()
            except Exception:
                pass
                
        logging.info("netcat clean exit completed.")
        QApplication.quit()
        sys.exit(0)

    def closeEvent(self, event):
        self.graceful_shutdown()
        event.accept()

    def setup_status_banner(self):
        self.status_banner = QWidget()
        self.status_banner.setStyleSheet("""
            QWidget {
                background-color: #1a1a32;
                border-top: 1px solid #333366;
                padding: 4px;
            }
            QLabel {
                color: #d1d1eb;
                font-size: 12px;
            }
            QPushButton {
                background-color: #29294a;
                border: 1px solid #444488;
                font-size: 11px;
                padding: 3px 8px;
            }
            QPushButton:hover {
                background-color: #00f3ff;
                color: #12121f;
                border: 1px solid #00f3ff;
            }
        """)
        
        banner_layout = QHBoxLayout(self.status_banner)
        banner_layout.setContentsMargins(10, 4, 10, 4)
        
        # Get active interface description
        iface_name = self.config.get("selected_interface")
        iface_desc = iface_name
        for iface in self.interfaces:
            if iface.name == iface_name:
                iface_desc = f"{iface.description} ({iface.ip})"
                break
                
        self.status_label = QLabel(f"Active Sniffer Interface: <b>{iface_desc}</b>. Not receiving traffic?")
        banner_layout.addWidget(self.status_label)
        
        self.change_iface_btn = QPushButton("Change Adapter")
        self.change_iface_btn.clicked.connect(self.switch_to_settings_tab)
        banner_layout.addWidget(self.change_iface_btn)
        
        banner_layout.addStretch()
        
        self.main_layout.addWidget(self.status_banner)

    def switch_to_settings_tab(self):
        # Settings & Rules is the 5th tab (index 4)
        self.tabs.setCurrentIndex(4)

    def setup_live_traffic_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Controls header for Pause/Resume
        controls_layout = QHBoxLayout()
        layout.addLayout(controls_layout)
        
        self.monitoring_status_label = QLabel("● Monitoring Status: ACTIVE")
        self.monitoring_status_label.setStyleSheet("color: #00f3ff; font-weight: bold; font-size: 12px;")
        controls_layout.addWidget(self.monitoring_status_label)
        
        controls_layout.addStretch()
        
        self.pause_resume_btn = QPushButton("⏸ Pause Monitoring")
        self.pause_resume_btn.clicked.connect(self.toggle_monitoring_status)
        controls_layout.addWidget(self.pause_resume_btn)
        
        self.traffic_table = QTableWidget()
        self.traffic_table.setColumnCount(8)
        self.traffic_table.setHorizontalHeaderLabels([
            "Time", "Source IP", "Dest IP", "Protocol", "Src Port", "Dst Port", "Application / Domain", "Size (B)"
        ])
        self.traffic_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.traffic_table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        self.traffic_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.traffic_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.traffic_table.setAlternatingRowColors(True)
        
        layout.addWidget(self.traffic_table)
        self.tabs.addTab(tab, "📡 Live Traffic")

    def toggle_monitoring_status(self):
        if self.capture_thread and self.capture_thread.is_alive():
            # Stop CaptureThread
            self.capture_thread.stop()
            self.capture_thread = None
            
            # Update UI
            self.monitoring_status_label.setText("○ Monitoring Status: PAUSED")
            self.monitoring_status_label.setStyleSheet("color: #ff4d4d; font-weight: bold; font-size: 12px;")
            self.pause_resume_btn.setText("▶ Resume Monitoring")
            
            logging.info("Monitoring paused by user")
        else:
            # Resume capture
            iface_name = self.config.get("selected_interface")
            if not iface_name:
                QMessageBox.warning(self, "No Interface Selected", "Cannot resume monitoring: No active interface selected.")
                return
                
            from netcat.capture import CaptureThread
            self.capture_thread = CaptureThread(iface_name, self.packet_queue)
            self.capture_thread.start()
            
            # Update UI
            self.monitoring_status_label.setText("● Monitoring Status: ACTIVE")
            self.monitoring_status_label.setStyleSheet("color: #00f3ff; font-weight: bold; font-size: 12px;")
            self.pause_resume_btn.setText("⏸ Pause Monitoring")
            
            logging.info("Monitoring resumed by user")

    def setup_threats_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Controls header for Auto-block toggle
        controls_layout = QHBoxLayout()
        layout.addLayout(controls_layout)
        
        self.auto_block_checkbox = QCheckBox("Enable Real-Time Auto-Blocking")
        self.auto_block_checkbox.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        self.auto_block_checkbox.setChecked(self.config.get("auto_block_enabled", True))
        self.auto_block_checkbox.stateChanged.connect(self.on_auto_block_toggle_changed)
        controls_layout.addWidget(self.auto_block_checkbox)
        
        controls_layout.addStretch()
        
        session_report_btn = QPushButton("Generate Session Report")
        session_report_btn.setStyleSheet("background-color: #1a1a3a; border: 1px solid #00f3ff; color: #00f3ff;")
        session_report_btn.clicked.connect(self.generate_session_report)
        controls_layout.addWidget(session_report_btn)
        
        self.threats_table = QTableWidget()
        self.threats_table.setColumnCount(6)
        self.threats_table.setHorizontalHeaderLabels([
            "Time", "Source IP", "Rule Triggered", "Severity", "Detail", "Actions"
        ])
        self.threats_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.threats_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self.threats_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.threats_table.setAlternatingRowColors(True)
        
        # Load historical threats from db
        historical_threats = self.db.get_all_threat_events(limit=50)
        for event in reversed(historical_threats):
            self.add_threat_row(event)
            
        layout.addWidget(self.threats_table)
        self.tabs.addTab(tab, "⚠️ Threats & Alerts")

    def on_auto_block_toggle_changed(self, state):
        is_checked = bool(state == Qt.CheckState.Checked.value)
        self.config.set("auto_block_enabled", is_checked)
        logging.info(f"Automatic blocking toggled by user: {'ENABLED' if is_checked else 'DISABLED'}")

    def setup_blocked_ips_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Controls header for Master Kill Switch
        kill_switch_layout = QHBoxLayout()
        layout.addLayout(kill_switch_layout)
        
        self.kill_switch_btn = QPushButton("🛑 Unblock All & Disable Auto-Block")
        self.kill_switch_btn.setStyleSheet("""
            QPushButton {
                background-color: #5c1d1d;
                border: 2px solid #993333;
                color: #ffcccc;
                padding: 10px 20px;
                font-weight: bold;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #8c2626;
                color: #ffffff;
                border: 2px solid #cc4444;
            }
        """)
        self.kill_switch_btn.clicked.connect(self.trigger_master_kill_switch)
        kill_switch_layout.addWidget(self.kill_switch_btn)
        kill_switch_layout.addStretch()
        
        self.blocked_table = QTableWidget()
        self.blocked_table.setColumnCount(5)
        self.blocked_table.setHorizontalHeaderLabels([
            "IP Address", "Backend Used", "Blocked At", "Reason", "Action"
        ])
        self.blocked_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.blocked_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.blocked_table.setAlternatingRowColors(True)
        
        layout.addWidget(self.blocked_table)
        self.tabs.addTab(tab, "🛡️ Blocked list")

    def trigger_master_kill_switch(self):
        active_blocks = self.block_manager.get_active_blocks()
        n_blocks = len(active_blocks)
        
        confirm = QMessageBox.question(
            self, "Confirm Kill Switch",
            f"Are you sure you want to trigger the Master Kill Switch?\n\nThis will unblock {n_blocks} currently-blocked IPs and disable automatic blocking.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if confirm == QMessageBox.StandardButton.Yes:
            # 1. Disable auto blocking in config
            self.config.set("auto_block_enabled", False)
            
            # Sync the auto block checkbox if it exists
            if hasattr(self, 'auto_block_checkbox'):
                self.auto_block_checkbox.blockSignals(True)
                self.auto_block_checkbox.setChecked(False)
                self.auto_block_checkbox.blockSignals(False)
                
            # 2. Iterate and unblock all IPs
            unblocked_ips = []
            for ip in list(active_blocks.keys()):
                success = self.block_manager.unblock_ip(ip, reason="Master kill switch triggered by user")
                if success:
                    unblocked_ips.append(ip)
                    logging.info(f"Kill switch unblocked IP: {ip}")
                    
            self.refresh_blocked_table()
            
            # Log summary
            logging.info(f"Kill switch triggered by user: {len(unblocked_ips)} IPs unblocked, auto-block disabled")
            
            QMessageBox.information(
                self, "Kill Switch Activated",
                f"Master Kill Switch successfully triggered:\n* Auto-blocking has been disabled.\n* {len(unblocked_ips)} IPs have been unblocked."
            )

    def setup_charts_tab(self):
        self.charts_widget = ChartsWidget()
        self.tabs.addTab(self.charts_widget, "📊 Analytics & Charts")

    def setup_settings_tab(self):
        tab = QWidget()
        layout = QHBoxLayout(tab)
        
        left_layout = QVBoxLayout()
        right_layout = QVBoxLayout()
        layout.addLayout(left_layout, 1)
        layout.addLayout(right_layout, 1)
        
        # Left Panel - Interface & Mode
        group_sys = QGroupBox("System settings")
        sys_layout = QFormLayout(group_sys)
        
        self.iface_combo = QComboBox()
        self.interfaces = list_interfaces()
        for idx, iface in enumerate(self.interfaces):
            self.iface_combo.addItem(str(iface), iface.name)
            if iface.name == self.config.get("selected_interface"):
                self.iface_combo.setCurrentIndex(idx)
        sys_layout.addRow("Monitoring Adapter:", self.iface_combo)
        
        self.block_mode_combo = QComboBox()
        self.block_mode_combo.addItems(["both", "firewall", "windivert", "none"])
        self.block_mode_combo.setCurrentText(self.config.get("block_mode"))
        sys_layout.addRow("Blocking Backend:", self.block_mode_combo)
        
        self.block_severity_combo = QComboBox()
        self.block_severity_combo.addItems(["none", "low", "medium", "high", "critical"])
        self.block_severity_combo.setCurrentText(self.config.get("auto_block_severity"))
        sys_layout.addRow("Auto-Block Threshold:", self.block_severity_combo)
        
        self.safe_mode_checkbox = QCheckBox("Run in SAFE MODE (Simulate Blocks)")
        self.safe_mode_checkbox.setChecked(self.config.get("safe_mode"))
        self.safe_mode_checkbox.stateChanged.connect(self.on_safe_mode_changed)
        sys_layout.addRow(self.safe_mode_checkbox)

        self.cpp_engine_checkbox = QCheckBox("Use C++ DPI Engine (faster, requires dpi_engine.exe)")
        self.cpp_engine_checkbox.setChecked(self.config.get("use_cpp_dpi_engine", False))
        self.cpp_engine_checkbox.stateChanged.connect(self.on_cpp_engine_toggled)
        sys_layout.addRow(self.cpp_engine_checkbox)
        
        self.save_sys_btn = QPushButton("Apply System Settings")
        self.save_sys_btn.clicked.connect(self.save_system_settings)
        sys_layout.addRow(self.save_sys_btn)
        left_layout.addWidget(group_sys)
        
        # Left Panel - Detection Thresholds
        group_rules = QGroupBox("Detection Rules Thresholds")
        rules_layout = QFormLayout(group_rules)
        
        self.port_scan_spin = QSpinBox()
        self.port_scan_spin.setRange(2, 100)
        self.port_scan_spin.setValue(self.config.get("port_scan_threshold"))
        rules_layout.addRow("Port Scan distinct ports:", self.port_scan_spin)
        
        self.syn_flood_spin = QSpinBox()
        self.syn_flood_spin.setRange(10, 1000)
        self.syn_flood_spin.setValue(self.config.get("syn_flood_threshold"))
        rules_layout.addRow("SYN Flood count (5s):", self.syn_flood_spin)
        
        self.icmp_flood_spin = QSpinBox()
        self.icmp_flood_spin.setRange(5, 500)
        self.icmp_flood_spin.setValue(self.config.get("icmp_flood_threshold"))
        rules_layout.addRow("ICMP Flood count (5s):", self.icmp_flood_spin)
        
        self.spike_spin = QSpinBox()
        self.spike_spin.setRange(50, 5000)
        self.spike_spin.setValue(self.config.get("traffic_spike_threshold"))
        rules_layout.addRow("Traffic Spike limit (pps):", self.spike_spin)
        
        self.save_rules_btn = QPushButton("Save Detection Thresholds")
        self.save_rules_btn.clicked.connect(self.save_rules_settings)
        rules_layout.addRow(self.save_rules_btn)
        left_layout.addWidget(group_rules)
        
        # Right Panel - Whitelist Management
        group_white = QGroupBox("Whitelist Protected IPs (Never Block)")
        white_layout = QVBoxLayout(group_white)
        self.white_list = QListWidget()
        self.refresh_whitelist()
        white_layout.addWidget(self.white_list)
        
        white_input_layout = QHBoxLayout()
        self.white_input = QLineEdit()
        self.white_input.setPlaceholderText("Enter IP address")
        white_input_layout.addWidget(self.white_input)
        self.add_white_btn = QPushButton("Add")
        self.add_white_btn.clicked.connect(self.add_whitelist_ip)
        white_input_layout.addWidget(self.add_white_btn)
        self.rem_white_btn = QPushButton("Remove Selected")
        self.rem_white_btn.clicked.connect(self.remove_whitelist_ip)
        white_input_layout.addWidget(self.rem_white_btn)
        white_layout.addLayout(white_input_layout)
        right_layout.addWidget(group_white)

        # Right Panel - DPI Block Rules
        group_dpi = QGroupBox("DPI Block Applications & Domains")
        dpi_layout = QVBoxLayout(group_dpi)
        
        app_list_layout = QGridLayout()
        self.app_checks = {}
        apps_to_list = [AppType.YOUTUBE, AppType.FACEBOOK, AppType.INSTAGRAM, AppType.NETFLIX, AppType.TIKTOK, AppType.SPOTIFY]
        
        blocked_apps = self.config.get("blocked_apps", [])
        for i, app in enumerate(apps_to_list):
            cb = QCheckBox(app)
            cb.setChecked(app in blocked_apps)
            cb.stateChanged.connect(self.save_dpi_app_rules)
            app_list_layout.addWidget(cb, i // 3, i % 3)
            self.app_checks[app] = cb
        dpi_layout.addLayout(app_list_layout)
        
        dpi_layout.addWidget(QLabel("Blocked Domains (Substring):"))
        self.domain_list = QListWidget()
        self.refresh_domain_list()
        dpi_layout.addWidget(self.domain_list)
        
        domain_input_layout = QHBoxLayout()
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("e.g. torrent, doubleclick")
        domain_input_layout.addWidget(self.domain_input)
        self.add_domain_btn = QPushButton("Block Domain")
        self.add_domain_btn.clicked.connect(self.add_blocked_domain)
        domain_input_layout.addWidget(self.add_domain_btn)
        self.rem_domain_btn = QPushButton("Unblock Selected")
        self.rem_domain_btn.clicked.connect(self.remove_blocked_domain)
        domain_input_layout.addWidget(self.rem_domain_btn)
        dpi_layout.addLayout(domain_input_layout)
        
        # Database wipe button
        self.clear_db_btn = QPushButton("🗑️ Clear Alert & Action logs")
        self.clear_db_btn.setStyleSheet("background-color: #3f1e1e; border: 1px solid #663333; color: #ebcdcd;")
        self.clear_db_btn.clicked.connect(self.clear_database_logs)
        dpi_layout.addWidget(self.clear_db_btn)
        
        right_layout.addWidget(group_dpi)
        
        self.tabs.addTab(tab, "⚙️ Settings & Rules")

    # --- UI Logic ---
    def poll_queues(self):
        # 1. Poll live traffic queue
        while not self.traffic_queue.empty():
            try:
                pkt = self.traffic_queue.get_nowait()
                self.add_traffic_row(pkt)
            except queue.Empty:
                break
                
        # 2. Poll alert queue
        while not self.alert_queue.empty():
            try:
                event = self.alert_queue.get_nowait()
                self.add_threat_row(event.to_dict() if hasattr(event, "to_dict") else event)
            except queue.Empty:
                break
                
        # 3. Poll stats queue
        while not self.stats_queue.empty():
            try:
                stats = self.stats_queue.get_nowait()
                self.charts_widget.update_charts(stats)
            except queue.Empty:
                break

    def add_traffic_row(self, pkt):
        # Insert at the top of the table
        self.traffic_table.insertRow(0)
        
        time_str = time.strftime("%H:%M:%S", time.localtime(pkt["timestamp"]))
        protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        proto_str = protocol_map.get(pkt["protocol"], str(pkt["protocol"]))
        
        # Check DPI classification
        app, domain = DPIEngine.classify_packet(pkt["protocol"], pkt["dst_port"], pkt["src_port"], pkt["payload"], pkt["src_ip"], pkt["dst_ip"])
            
        app_domain_str = app
        if domain:
            app_domain_str += f" ({domain})"
            
        self.traffic_table.setItem(0, 0, QTableWidgetItem(time_str))
        self.traffic_table.setItem(0, 1, QTableWidgetItem(pkt["src_ip"]))
        self.traffic_table.setItem(0, 2, QTableWidgetItem(pkt["dst_ip"]))
        self.traffic_table.setItem(0, 3, QTableWidgetItem(proto_str))
        self.traffic_table.setItem(0, 4, QTableWidgetItem(str(pkt["src_port"]) if pkt["src_port"] else ""))
        self.traffic_table.setItem(0, 5, QTableWidgetItem(str(pkt["dst_port"]) if pkt["dst_port"] else ""))
        self.traffic_table.setItem(0, 6, QTableWidgetItem(app_domain_str))
        self.traffic_table.setItem(0, 7, QTableWidgetItem(str(pkt["length"])))
        
        # Keep table size bounded
        if self.traffic_table.rowCount() > 100:
            self.traffic_table.removeRow(self.traffic_table.rowCount() - 1)

    def add_threat_row(self, event):
        self.threats_table.insertRow(0)
        
        # Time format
        time_str = event["timestamp"].split("T")[-1] if "T" in event["timestamp"] else event["timestamp"]
        
        # Items
        self.threats_table.setItem(0, 0, QTableWidgetItem(time_str))
        
        ip_item = QTableWidgetItem(event["src_ip"])
        ip_item.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        self.threats_table.setItem(0, 1, ip_item)
        
        self.threats_table.setItem(0, 2, QTableWidgetItem(event["rule"]))
        
        sev_item = QTableWidgetItem(event["severity"].upper())
        sev_item.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        # Color coding
        colors = {
            "low": QColor("#00ff99"),       # Greenish
            "medium": QColor("#ffaa00"),    # Orange
            "high": QColor("#ff4444"),      # Red
            "critical": QColor("#ff00f3")   # Magenta
        }
        sev_item.setForeground(colors.get(event["severity"].lower(), QColor("#ffffff")))
        self.threats_table.setItem(0, 3, sev_item)
        
        self.threats_table.setItem(0, 4, QTableWidgetItem(event["detail"]))
        
        # Action Buttons Layout
        actions_widget = QWidget()
        actions_layout = QHBoxLayout(actions_widget)
        actions_layout.setContentsMargins(0, 0, 0, 0)
        actions_layout.setSpacing(4)
        
        block_btn = QPushButton("Block")
        block_btn.setStyleSheet("background-color: #3f1e1e; border: 1px solid #663333; font-size: 11px;")
        block_btn.clicked.connect(lambda checked, ip=event["src_ip"]: self.manual_block_ip(ip))
        
        white_btn = QPushButton("Whitelist")
        white_btn.setStyleSheet("background-color: #1e3f2d; border: 1px solid #33664d; font-size: 11px;")
        white_btn.clicked.connect(lambda checked, ip=event["src_ip"]: self.manual_whitelist_ip(ip))
        
        report_btn = QPushButton("Report")
        report_btn.setStyleSheet("background-color: #1e2d3f; border: 1px solid #334d66; font-size: 11px;")
        report_btn.clicked.connect(lambda checked, ev=event: self.view_incident_report(ev))
        
        actions_layout.addWidget(block_btn)
        actions_layout.addWidget(white_btn)
        actions_layout.addWidget(report_btn)
        self.threats_table.setCellWidget(0, 5, actions_widget)
        
        if self.threats_table.rowCount() > 100:
            self.threats_table.removeRow(self.threats_table.rowCount() - 1)

    def view_incident_report(self, event):
        alert_id = event.get("alert_id") or event.get("id")
        if not alert_id:
            QMessageBox.warning(self, "Report Not Found", "No alert reference ID is associated with this threat event.")
            return
            
        reports_dir = os.path.join(os.getcwd(), "reports")
        md_path = os.path.join(reports_dir, f"{alert_id}.md")
        pdf_path = os.path.join(reports_dir, f"{alert_id}.pdf")
        
        if os.path.exists(md_path):
            try:
                with open(md_path, 'r', encoding='utf-8') as f:
                    md_text = f.read()
                
                from PyQt6.QtWidgets import QDialog, QTextEdit
                dialog = QDialog(self)
                dialog.setWindowTitle(f"NETCAT Incident Forensic Report - Alert #{alert_id}")
                dialog.resize(750, 600)
                
                layout = QVBoxLayout(dialog)
                text_edit = QTextEdit()
                text_edit.setReadOnly(True)
                text_edit.setMarkdown(md_text)
                layout.addWidget(text_edit)
                
                open_pdf_btn = QPushButton("Open PDF Report")
                open_pdf_btn.clicked.connect(lambda: os.startfile(pdf_path) if os.path.exists(pdf_path) else QMessageBox.warning(dialog, "PDF Missing", "PDF summary not found."))
                layout.addWidget(open_pdf_btn)
                
                dialog.exec()
            except Exception as e:
                QMessageBox.critical(self, "Error Reading Report", f"Failed to view Markdown report: {e}")
        else:
            json_blob = self.db.get_threat_analysis(alert_id)
            if json_blob:
                try:
                    js = json.loads(json_blob)
                    from PyQt6.QtWidgets import QDialog, QTextEdit
                    dialog = QDialog(self)
                    dialog.setWindowTitle(f"NETCAT Forensic Log - Alert #{alert_id}")
                    dialog.resize(600, 500)
                    
                    layout = QVBoxLayout(dialog)
                    text_edit = QTextEdit()
                    text_edit.setReadOnly(True)
                    text_edit.setPlainText(json.dumps(js, indent=4))
                    layout.addWidget(text_edit)
                    dialog.exec()
                except Exception as e:
                    QMessageBox.critical(self, "Error Displaying JSON", f"Failed to display inline JSON data: {e}")
            else:
                QMessageBox.information(self, "Report Generating", "Forensic analysis report is currently generating in the background. Please wait a few seconds and try again.")

    def generate_session_report(self):
        threat_events = self.db.get_all_threat_events(limit=100)
        if not threat_events:
            QMessageBox.information(self, "No Incidents", "There are no threat events logged in this session to generate a report.")
            return
            
        from netcat.detector import ThreatEvent
        events_list = []
        for ev in threat_events:
            events_list.append(ThreatEvent(
                timestamp=ev["timestamp"],
                src_ip=ev["src_ip"],
                rule=ev["rule"],
                severity=ev["severity"],
                detail=ev["detail"],
                alert_id=ev.get("id") or ev.get("alert_id")
            ))
            
        try:
            from netcat.report_generator import ReportGenerator
            md_path, pdf_path = ReportGenerator.generate_combined_session_report(events_list)
            
            msg_box = QMessageBox(self)
            msg_box.setWindowTitle("Session Report Generated")
            msg_box.setText(f"Session summary report successfully generated!\n\nSaved to:\n- {md_path}\n- {pdf_path}")
            
            open_md_btn = msg_box.addButton("Open Markdown Summary", QMessageBox.ButtonRole.ActionRole)
            open_pdf_btn = msg_box.addButton("Open PDF Summary", QMessageBox.ButtonRole.ActionRole)
            close_btn = msg_box.addButton("Close", QMessageBox.ButtonRole.RejectRole)
            
            msg_box.exec()
            
            if msg_box.clickedButton() == open_md_btn:
                os.startfile(md_path)
            elif msg_box.clickedButton() == open_pdf_btn:
                os.startfile(pdf_path)
        except Exception as e:
            QMessageBox.critical(self, "Error Generating Session Report", f"Failed to generate combined session report: {e}")

    def refresh_blocked_table(self):
        self.blocked_table.setRowCount(0)
        blocks = self.block_manager.get_active_blocks()
        
        for ip, info in blocks.items():
            row = self.blocked_table.rowCount()
            self.blocked_table.insertRow(row)
            
            time_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(info["timestamp"]))
            
            self.blocked_table.setItem(row, 0, QTableWidgetItem(ip))
            self.blocked_table.setItem(row, 1, QTableWidgetItem(info["backend"]))
            self.blocked_table.setItem(row, 2, QTableWidgetItem(time_str))
            self.blocked_table.setItem(row, 3, QTableWidgetItem(info["reason"]))
            
            unblock_btn = QPushButton("Unblock")
            unblock_btn.setStyleSheet("background-color: #1e283f; border: 1px solid #334466; font-size: 11px;")
            unblock_btn.clicked.connect(lambda checked, ip_addr=ip: self.manual_unblock_ip(ip_addr))
            self.blocked_table.setCellWidget(row, 4, unblock_btn)

    def refresh_whitelist(self):
        self.white_list.clear()
        self.white_list.addItems(self.config.get("whitelist_ips"))

    def refresh_domain_list(self):
        self.domain_list.clear()
        self.domain_list.addItems(self.config.get("blocked_domains"))

    # --- Button Callbacks ---
    def manual_block_ip(self, ip):
        if self.config.is_whitelisted(ip):
            QMessageBox.warning(self, "Blocking Protected IP", f"Cannot block {ip} as it is in the Whitelist.")
            return
            
        success = self.block_manager.block_ip(ip, reason="Manually blocked from Threats feed")
        if success:
            QMessageBox.information(self, "Block Successful", f"Successfully blocked source IP {ip}.")
            self.refresh_blocked_table()
        else:
            QMessageBox.warning(self, "Block Failed", f"Could not block IP {ip} (is it already blocked?).")

    def manual_unblock_ip(self, ip):
        success = self.block_manager.unblock_ip(ip, reason="Manually unblocked from Blocked list")
        if success:
            QMessageBox.information(self, "Unblock Successful", f"Successfully unblocked IP {ip}.")
            self.refresh_blocked_table()
        else:
            QMessageBox.warning(self, "Unblock Failed", f"Could not unblock IP {ip}.")

    def manual_whitelist_ip(self, ip):
        # First unblock if blocked
        if self.config.is_blocked(ip):
            self.block_manager.unblock_ip(ip, reason="Unblocked to allow Whitelisting")
            
        success = self.config.add_to_whitelist(ip)
        if success:
            QMessageBox.information(self, "Whitelist Successful", f"Added {ip} to whitelist.")
            self.refresh_whitelist()
            self.refresh_blocked_table()
        else:
            QMessageBox.warning(self, "Whitelist Failed", f"IP {ip} is already whitelisted.")

    def on_safe_mode_changed(self, state):
        is_checked = bool(state == Qt.CheckState.Checked.value)
        self.config.set("safe_mode", is_checked)
        self.update_safe_mode_header()
        if is_checked:
            self.block_manager.clean_all_blocks()
            self.refresh_blocked_table()
            QMessageBox.information(self, "Safe Mode Enabled", "Auto-blocking has been disabled. All active firewall and WinDivert blocks have been safely cleared.")

    def on_cpp_engine_toggled(self, state):
        is_checked = bool(state == Qt.CheckState.Checked.value)
        if is_checked:
            exe_path = os.path.join(os.getcwd(), "dpi_engine.exe")
            if not os.path.exists(exe_path):
                QMessageBox.warning(
                    self, "dpi_engine.exe Not Found",
                    f"Cannot enable the C++ DPI engine: dpi_engine.exe was not found at:\n{exe_path}\n\n"
                    "Please place dpi_engine.exe in the project root and try again."
                )
                self.cpp_engine_checkbox.blockSignals(True)
                self.cpp_engine_checkbox.setChecked(False)
                self.cpp_engine_checkbox.blockSignals(False)
                return
        self.config.set("use_cpp_dpi_engine", is_checked)
        engine_name = "C++ DPI Engine (dpi_engine.exe)" if is_checked else "Python DPI Engine (dpi.py)"
        QMessageBox.information(
            self, "DPI Engine Changed",
            f"DPI engine set to: {engine_name}.\n\n"
            "A full application restart is required for this change to take effect cleanly, "
            "as the engine worker thread only re-checks this setting after its current subprocess exits."
        )

    def save_system_settings(self):
        # 1. Interface
        sel_name = self.iface_combo.currentData()
        self.config.set("selected_interface", sel_name)
        
        # 2. Block Mode
        self.config.set("block_mode", self.block_mode_combo.currentText())
        
        # 3. Auto-block Severity
        self.config.set("auto_block_severity", self.block_severity_combo.currentText())
        
        QMessageBox.information(self, "Settings Saved", "System settings have been successfully applied. Please restart monitor thread to use new network adapter.")

    def save_rules_settings(self):
        self.config.set("port_scan_threshold", self.port_scan_spin.value())
        self.config.set("syn_flood_threshold", self.syn_flood_spin.value())
        self.config.set("icmp_flood_threshold", self.icmp_flood_spin.value())
        self.config.set("traffic_spike_threshold", self.spike_spin.value())
        
        QMessageBox.information(self, "Thresholds Applied", "Behavioral rule thresholds updated.")

    def add_whitelist_ip(self):
        ip = self.white_input.text().strip()
        if not ip:
            return
        # Basic validation
        octets = ip.split(".")
        if len(octets) != 4 or not all(o.isdigit() and 0 <= int(o) <= 255 for o in octets):
            QMessageBox.critical(self, "Invalid IP Format", "Please enter a valid IPv4 address.")
            return
            
        self.manual_whitelist_ip(ip)
        self.white_input.clear()

    def remove_whitelist_ip(self):
        selected = self.white_list.currentItem()
        if not selected:
            return
        ip = selected.text()
        # Protected basic whitelist
        if ip in ["127.0.0.1", "0.0.0.0"]:
            QMessageBox.warning(self, "Protected IP", f"Cannot remove default system loopback {ip} from whitelist.")
            return
            
        self.config.remove_from_whitelist(ip)
        self.refresh_whitelist()
        QMessageBox.information(self, "Removed", f"IP {ip} removed from Whitelist.")

    def save_dpi_app_rules(self):
        blocked_apps = []
        for app, cb in self.app_checks.items():
            if cb.isChecked():
                blocked_apps.append(app)
        self.config.set("blocked_apps", blocked_apps)

    def add_blocked_domain(self):
        dom = self.domain_input.text().strip().lower()
        if not dom:
            return
            
        blocked_domains = self.config.get("blocked_domains", [])
        if dom not in blocked_domains:
            blocked_domains.append(dom)
            self.config.set("blocked_domains", blocked_domains)
            self.refresh_domain_list()
            QMessageBox.information(self, "Domain Blocked", f"Successfully added {dom} to domain blocklist.")
        self.domain_input.clear()

    def remove_blocked_domain(self):
        selected = self.domain_list.currentItem()
        if not selected:
            return
        dom = selected.text()
        
        blocked_domains = self.config.get("blocked_domains", [])
        if dom in blocked_domains:
            blocked_domains.remove(dom)
            self.config.set("blocked_domains", blocked_domains)
            self.refresh_domain_list()
            QMessageBox.information(self, "Domain Unblocked", f"Successfully removed {dom} from domain blocklist.")

    def clear_database_logs(self):
        reply = QMessageBox.question(
            self, "Clear Logs Confirmation", "Are you sure you want to permanently clear all Database logs (Threat alerts & blocking history)?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.db.clear_logs()
            self.threats_table.setRowCount(0)
            QMessageBox.information(self, "Logs Cleared", "SQLite database logs cleared.")

    def closeEvent(self, event):
        # Cleanup blocking rules on exit to avoid locking user network
        self.block_manager.clean_all_blocks()
        event.accept()
