# bismarck-otto 2025-08-09 to calculate hash with readCert.ps1

# Copyright (c) 2025 Otto von Bismarck
# This project includes portions generated using OpenAI’s ChatGPT.
# All code is released under the MIT License.

# Show recipient certificate info from a certificate-encrypted PDF.
# Displays a MessageBox and copies serial(s) to the clipboard.
# ================================================================
#
# Nota Bene: Works in PowerShell 7.5.2 (not in 5.1)
#
# Create a shortcut in the SendTo folder:
# a) Press Win + R, type shell:sendto, press Enter.
# b) Right-click in the folder → New > Shortcut.
# c) Point it to/Type the location to the item:
#    pwsh.exe -ExecutionPolicy Bypass -File "C:\Path\To\readCert.ps1"
# d) Replace C:\Path\To\ with the actual path to your readCert.ps1 file.
# e) Name it something like 'Read PDF Recipient Certificates'.
# f) Right-click on the new shortcut → Properties > Run: 'Mimimized'.
