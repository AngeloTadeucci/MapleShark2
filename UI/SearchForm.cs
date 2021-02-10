﻿using System;
using System.Collections.Generic;
using System.Drawing;
using System.Windows.Forms;
using Be.Windows.Forms;
using MapleShark2.Logging;
using MapleShark2.Theme;
using MapleShark2.Tools;
using WeifenLuo.WinFormsUI.Docking;

namespace MapleShark2.UI {
    public partial class SearchForm : DockContent {
        public MainForm MainForm => ParentForm as MainForm;

        public SearchForm() {
            InitializeComponent();
            ScaleFormHeight();

            hexInput.ByteProvider = new DynamicByteProvider(new List<byte>());
            hexInput.ByteProvider.Changed += hexInput_ByteProviderChanged;
        }

        // Fix height when using screen scaling.
        private void ScaleFormHeight() {
            float scale = CreateGraphics().DpiX / 96 * 0.9f;
            if (scale > 1.0f) {
                hexInput.Height = (int) (hexInput.Height * scale);
                btnPrevSequence.Height = (int) (btnPrevSequence.Height * scale);
                btnNextSequence.Height = (int) (btnNextSequence.Height * scale);
            }
        }

        public new void Show(DockPanel panel) {
            base.Show(panel);
            BackColor = Config.Instance.Theme.DockSuiteTheme.ColorPalette.MainWindowActive.Background;
            ThemeApplier.ApplyTheme(Config.Instance.Theme, Controls);
        }

        public void RefreshOpcodes(bool pReselect) {
            if (!(DockPanel.ActiveDocument is SessionForm session)) {
                dropdownOpcode.Items.Clear();
                return;
            }

            Opcode selected =
                pReselect
                && dropdownOpcode.SelectedIndex >= 0
                && session.Opcodes.Count > dropdownOpcode.SelectedIndex
                    ? session.Opcodes[dropdownOpcode.SelectedIndex]
                    : null;
            dropdownOpcode.Items.Clear();
            session.UpdateOpcodeList();

            foreach (Opcode op in session.Opcodes) {
                Definition definition =
                    Config.Instance.GetDefinition(session.Build, session.Locale, op.Outbound, op.Header);
                int addedIndex = dropdownOpcode.Items.Add(
                    $"{(op.Outbound ? "OUT " : "IN  ")} 0x{op.Header:X4} {definition?.Name ?? ""}");

                if (selected != null && selected.Outbound == op.Outbound && selected.Header == op.Header) {
                    dropdownOpcode.SelectedIndex = addedIndex;
                }
            }
        }

        public void ClearOpcodes() {
            dropdownOpcode.Items.Clear();
        }

        public void SetHexBoxBytes(byte[] bytes) {
            hexInput.ByteProvider = new DynamicByteProvider(bytes);
            hexInput.ByteProvider.Changed += hexInput_ByteProviderChanged;
        }

        private void dropdownOpcode_SelectedIndexChanged(object pSender, EventArgs pArgs) {
            btnNextOpcode.Enabled = btnPrevOpcode.Enabled = dropdownOpcode.SelectedIndex >= 0;
        }

        // Custom rendering for combobox
        private void dropdownOpcode_DrawItem(object sender, DrawItemEventArgs e) {
            Brush backBrush, foreBrush;
            if ((e.State & DrawItemState.Selected) > 0) {
                backBrush = SystemBrushes.Highlight;
                foreBrush = SystemBrushes.HighlightText;
            } else {
                backBrush = new SolidBrush(dropdownOpcode.BackColor);
                foreBrush = new SolidBrush(dropdownOpcode.ForeColor);
            }

            e.DrawBackground();
            e.Graphics.FillRectangle(backBrush, e.Bounds);

            int index = e.Index >= 0 ? e.Index : -1;
            if (index != -1) {
                e.Graphics.DrawString(dropdownOpcode.Items[index].ToString(), e.Font, foreBrush, e.Bounds,
                    StringFormat.GenericDefault);
            }

            e.DrawFocusRectangle();
        }

        private void btnNextOpcode_Click(object pSender, EventArgs pArgs) {
            if (!(DockPanel.ActiveDocument is SessionForm session) || dropdownOpcode.SelectedIndex == -1) {
                return;
            }

            Opcode search = session.Opcodes[dropdownOpcode.SelectedIndex];
            int initialIndex = session.ListView.SelectedIndices.Count == 0
                ? 0
                : session.ListView.SelectedIndices[0] + 1;
            for (int index = initialIndex; index < session.ListView.VirtualListSize; ++index) {
                MaplePacket packetItem = session.FilteredPackets[index];
                if (packetItem.Outbound == search.Outbound && packetItem.Opcode == search.Header) {
                    session.ListView.Select(index);
                    session.ListView.Focus();
                    return;
                }
            }

            MessageBox.Show("No further packets found with the selected opcode.", "End Of Search", MessageBoxButtons.OK,
                MessageBoxIcon.Information);
            session.ListView.Focus();
        }

        private void hexInput_ByteProviderChanged(object pSender, EventArgs pArgs) {
            btnNextSequence.Enabled /* = btnPrevSequence.Enabled */ = hexInput.ByteProvider.Length > 0;
        }

        private void hexInput_KeyPress(object pSender, KeyPressEventArgs pArgs) {
            if (pArgs.KeyChar == (char) Keys.Enter) {
                pArgs.Handled = true;
                NextSequence();
            }
        }

        private void btnNextSequence_Click(object pSender, EventArgs pArgs) {
            NextSequence();
        }

        private void NextSequence() {
            if (!(DockPanel.ActiveDocument is SessionForm session)) {
                return;
            }

            int initialIndex = session.ListView.SelectedIndices.Count == 0 ? 0 : session.ListView.SelectedIndices[0];
            byte[] pattern = (hexInput.ByteProvider as DynamicByteProvider)?.Bytes.ToArray();
            long startIndex = MainForm.DataForm.SelectionLength > 0 ? MainForm.DataForm.SelectionStart : -1;
            for (int index = initialIndex; index < session.ListView.VirtualListSize; ++index) {
                MaplePacket packetItem = session.FilteredPackets[index];
                long searchIndex = startIndex + 1;
                bool found = false;
                while (pattern != null && searchIndex <= packetItem.Length - pattern.Length) {
                    found = true;
                    for (int patternIndex = 0; found && patternIndex < pattern.Length; ++patternIndex)
                        found = packetItem.AsSpan()[(int) (searchIndex + patternIndex)] == pattern[patternIndex];
                    if (found) break;
                    ++searchIndex;
                }

                if (found) {
                    session.ListView.Select(index);
                    MainForm.DataForm.SelectHexBoxRange(searchIndex, pattern.Length);
                    session.ListView.Focus();
                    return;
                }

                startIndex = -1;
            }

            MessageBox.Show("No further sequences found.", "End Of Search", MessageBoxButtons.OK,
                MessageBoxIcon.Information);
            session.ListView.Focus();
        }

        private void btnPrevOpcode_Click(object sender, EventArgs e) {
            if (!(DockPanel.ActiveDocument is SessionForm session) || dropdownOpcode.SelectedIndex == -1) {
                return;
            }

            Opcode search = session.Opcodes[dropdownOpcode.SelectedIndex];
            int initialIndex = session.ListView.SelectedIndices.Count == 0 ? 0 : session.ListView.SelectedIndices[0];
            for (int index = initialIndex - 1; index > 0; --index) {
                MaplePacket packetItem = session.FilteredPackets[index];
                if (packetItem.Outbound == search.Outbound && packetItem.Opcode == search.Header) {
                    session.ListView.Select(index);
                    session.ListView.Focus();
                    return;
                }
            }

            MessageBox.Show("No further packets found with the selected opcode.", "End Of Search", MessageBoxButtons.OK,
                MessageBoxIcon.Information);
            session.ListView.Focus();
        }

        private void SearchForm_Load(object sender, EventArgs e) { }
    }
}