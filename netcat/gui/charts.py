import pyqtgraph as pg
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QGridLayout
from collections import deque
import numpy as np

# Apply dark theme stylesheet styles to pyqtgraph
pg.setConfigOption('background', '#181824')  # Sleek dark background
pg.setConfigOption('foreground', '#d0d0eb')  # Light text

class ChartsWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.layout = QVBoxLayout(self)
        
        # Grid layout to organize the 3 charts
        self.grid_layout = QGridLayout()
        self.layout.addLayout(self.grid_layout)
        
        # 1. PPS History Plot
        self.pps_plot = pg.PlotWidget(title="Packets Per Second (PPS)")
        self.pps_plot.showGrid(x=True, y=True, alpha=0.2)
        self.pps_plot.setLabel('left', 'PPS')
        self.pps_plot.setLabel('bottom', 'Seconds Ago')
        self.pps_plot.setXRange(-60, 0)
        # Create neon teal line
        self.pps_curve = self.pps_plot.plot(pen=pg.mkPen(color='#00f3ff', width=2.5))
        
        self.pps_data = deque([0] * 61, maxlen=61)
        self.grid_layout.addWidget(self.pps_plot, 0, 0, 1, 2) # Spans 2 columns
        
        # 2. Top Talkers Bar Plot
        self.talkers_plot = pg.PlotWidget(title="Top Talkers (Source IPs)")
        self.talkers_plot.showGrid(y=True, alpha=0.2)
        self.talkers_plot.setLabel('left', 'Packets')
        self.talkers_bar = None
        self.grid_layout.addWidget(self.talkers_plot, 1, 0)
        
        # 3. Application Breakdown Bar Plot
        self.app_plot = pg.PlotWidget(title="Application Protocol Traffic")
        self.app_plot.showGrid(y=True, alpha=0.2)
        self.app_plot.setLabel('left', 'Packets')
        self.app_bar = None
        self.grid_layout.addWidget(self.app_plot, 1, 1)

    def update_charts(self, stats):
        if not stats:
            return
            
        # Update PPS Chart
        pps = stats.get("pps", 0)
        self.pps_data.append(pps)
        
        # Plot data goes from -60 to 0 seconds ago
        x_data = np.arange(-60, 1)
        y_data = np.array(list(self.pps_data))
        self.pps_curve.setData(x_data, y_data)
        
        # Update Top Talkers Chart
        top_talkers = stats.get("top_talkers", [])
        self.talkers_plot.clear()
        if top_talkers:
            ips = [t[0] for t in top_talkers]
            counts = [t[1] for t in top_talkers]
            
            x = np.arange(len(ips))
            # Orange bar chart
            bg = pg.BarGraphItem(x=x, height=counts, width=0.5, brush=pg.mkBrush('#ff9f43'))
            self.talkers_plot.addItem(bg)
            
            # Label the ticks on bottom axis
            ax = self.talkers_plot.getAxis('bottom')
            ax.setTicks([[(i, ip) for i, ip in enumerate(ips)]])
        else:
            self.talkers_plot.getAxis('bottom').setTicks([])

        # Update App Breakdown Chart
        app_breakdown = stats.get("app_breakdown", {})
        self.app_plot.clear()
        if app_breakdown:
            # Sort apps by count to show top apps
            sorted_apps = sorted(app_breakdown.items(), key=lambda x: x[1], reverse=True)[:5]
            apps = [a[0] for a in sorted_apps]
            counts = [a[1] for a in sorted_apps]
            
            x = np.arange(len(apps))
            # Violet/Purple bar chart
            bg = pg.BarGraphItem(x=x, height=counts, width=0.5, brush=pg.mkBrush('#9b5de5'))
            self.app_plot.addItem(bg)
            
            # Label ticks
            ax = self.app_plot.getAxis('bottom')
            ax.setTicks([[(i, app) for i, app in enumerate(apps)]])
        else:
            self.app_plot.getAxis('bottom').setTicks([])
