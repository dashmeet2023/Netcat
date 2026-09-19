import sys
from fpdf import FPDF

pdf = FPDF()
pdf.add_page()

pdf.set_fill_color(26, 54, 93) # Dark Navy Blue
pdf.rect(0, 0, 210, 25, 'F')
pdf.set_font('helvetica', 'B', 15)
pdf.set_text_color(255, 255, 255)
pdf.set_y(8)
pdf.cell(w=0, h=10, text='NETCAT INSTALLATION & STARTUP GUIDE', align='C', new_x='LMARGIN', new_y='NEXT')
pdf.ln(15)
pdf.set_text_color(45, 55, 72)

pdf.set_font('helvetica', 'B', 12)
pdf.cell(w=0, h=10, text='1. Install Python & Dependencies', new_x='LMARGIN', new_y='NEXT')
pdf.set_font('helvetica', '', 11)
txt1 = "The project comes with a PowerShell script that sets up a portable Python 3.11 environment and installs all required dependencies (pyqt6, scapy, pydivert)."
pdf.multi_cell(w=0, h=6, text=txt1)
pdf.ln(2)
pdf.set_font('courier', '', 10)
pdf.multi_cell(w=0, h=6, text="Open a PowerShell terminal in the project directory (d:\\Netcat) and run:\n.\\install_python.ps1")
pdf.ln(8)
pdf.set_font('helvetica', 'B', 12)
pdf.cell(w=0, h=10, text='2. Run the Application', new_x='LMARGIN', new_y='NEXT')
pdf.set_font('helvetica', '', 11)
txt2 = "Because this application captures network packets and performs active blocking, you MUST run it with Administrator privileges."
pdf.multi_cell(w=0, h=6, text=txt2)
pdf.ln(2)
pdf.set_font('courier', '', 10)
pdf.multi_cell(w=0, h=6, text="Open an elevated (Administrator) PowerShell terminal, navigate to d:\\Netcat, and execute:\npython netcat_app.py")
pdf.ln(8)
pdf.set_font('helvetica', 'B', 12)
pdf.cell(w=0, h=10, text='3. C++ DPI Engine (Optional)', new_x='LMARGIN', new_y='NEXT')
pdf.set_font('helvetica', '', 11)
txt3 = "This project relies on a C++ Deep Packet Inspection (DPI) engine (dpi_engine.exe)."
pdf.multi_cell(w=0, h=6, text=txt3)
pdf.ln(2)
pdf.set_font('courier', '', 10)
pdf.multi_cell(w=0, h=6, text="If you need to rebuild it, you can run:\npython netcat_app.py --build-dpi-engine")
pdf.ln(2)
pdf.set_font('helvetica', 'I', 10)
pdf.multi_cell(w=0, h=6, text="Note: Compiling requires a C++ compiler (Visual Studio or MinGW) and CMake. See BUILD_STATUS.md for detailed compilation instructions.")

pdf.output('d:/Netcat/Netcat_Startup_Guide.pdf')
