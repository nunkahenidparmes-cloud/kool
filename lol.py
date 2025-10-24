#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Adapted from original script

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional, Tuple

# Import PyQt6 modules
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout,
    QHBoxLayout, QLabel, QPushButton, QLineEdit,
    QTextEdit, QMessageBox, QFileDialog, QSizePolicy
)
from PyQt6.QtCore import (
    QObject, QThread, pyqtSignal, Qt
)
from PyQt6.QtGui import QPixmap, QImage, QFont

# Import smartcard modules
try:
    from smartcard.System import readers
    from smartcard.util import toHexString
except ImportError:
    print("Error: 'smartcard' library not found. Please run: pip install python-smartcard")
    sys.exit(1)

# --- QSS STYLESHEET (ส่วนที่ทำให้ UI สวยงาม) ---

QSS_STYLE = """
/* BASE STYLES */
QWidget {
    background-color: #f0f4f8; /* Very light background */
    color: #2c3e50; /* Dark text for contrast */
    font-family: 'Segoe UI', 'Tahoma', 'sans-serif';
    font-size: 10pt;
}

QMainWindow {
    border: 1px solid #bdc3c7;
}

/* ACCENT COLOR & BUTTONS */
QPushButton {
    background-color: #3498db; /* Primary Blue Accent */
    color: white;
    border: 1px solid #2980b9;
    border-radius: 8px; /* Rounded corners */
    padding: 10px 20px;
    min-height: 30px;
    font-size: 10pt;
    font-weight: bold;
}
QPushButton:hover {
    background-color: #2980b9; /* Darker blue on hover */
}
QPushButton:pressed {
    background-color: #2c3e50;
}
QPushButton:disabled {
    background-color: #bdc3c7;
    border: 1px solid #95a5a6;
    color: #7f8c8d;
}

/* DATA FIELDS */
QLineEdit, QTextEdit {
    background-color: white;
    border: 1px solid #bdc3c7;
    border-radius: 5px;
    padding: 5px;
}
QLineEdit:read-only, QTextEdit:read-only {
    background-color: #ecf0f1; /* Slightly greyed out for read-only */
    color: #2c3e50;
}

/* LABELS & HEADERS */
QLabel {
    padding: 0;
    margin: 0;
}
#HeaderLabel {
    font-size: 14pt;
    font-weight: bold;
    color: #34495e;
    padding-bottom: 10px;
}

/* PHOTO FRAME */
#PhotoLabel {
    border: 3px solid #3498db; /* Highlight photo with accent color */
    background-color: #ecf0f1;
    border-radius: 10px;
    min-width: 200px;
    min-height: 250px;
}

/* WIDGET PANELS (for structure) */
#LeftPanelWidget, #RightPanelWidget {
    background-color: #ffffff;
    border-radius: 10px;
    padding: 20px;
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
}
"""


def load_stylesheet(app):
    """Applies the custom QSS stylesheet to the application."""
    app.setStyleSheet(QSS_STYLE)


# --- COMMON APDU CONSTANTS & UTILITIES ---

APDU_SELECT_COMMAND = [0x00, 0xA4, 0x04, 0x00, 0x08]
APDU_APPLET_ID = [0xA0, 0x00, 0x00, 0x00, 0x54, 0x48, 0x00, 0x01]
SW_SUCCESS = [0x90, 0x00]


def thai2unicode(data: List[int]) -> str:
    """Decodes TIS-620 bytes to Unicode, replacing '#' with spaces and stripping whitespace."""
    return (
        bytes(data)
        .decode('tis-620', errors='replace')
        .replace('#', ' ')
        .strip()
    )


def format_date(date_str: str) -> str:
    """
    Converts date string from 'YYYYMMDD' (Thai Buddhist Era) to 'DD/MM/YYYY'.
    E.g., 25500907 -> 07/09/2550
    """
    date_str = date_str.strip()
    if len(date_str) == 8 and date_str.isdigit():
        year = date_str[0:4]
        month = date_str[4:6]
        day = date_str[6:8]
        return f"{day}/{month}/{year}"
    return date_str  # Return original string if format is invalid


@dataclass(frozen=True)
class APDUCommand:
    """Represents an APDU command for reading a specific field from the card."""
    ins: List[int]
    label: str
    decoder: Callable[[List[int]], str] = thai2unicode


class SmartCardError(Exception):
    """Custom exception for smart card related errors."""
    pass


# --- SMART CARD CORE CLASSES ---

class SmartCardConnection:

    def __init__(self, connection):
        self.conn = connection
        self.get_response_apdu_prefix: List[int] = []

    def connect(self) -> None:
        self.conn.connect()
        atr = self.conn.getATR()
        self.get_response_apdu_prefix = [0x00, 0xC0, 0x00, 0x01] if atr[:2] == [0x3B, 0x67] else [0x00, 0xC0, 0x00,
                                                                                                  0x00]

    def transmit(self, apdu: List[int]) -> Tuple[List[int], int, int]:
        return self.conn.transmit(apdu)

    def disconnect(self):
        if self.conn:
            self.conn.disconnect()


@dataclass
class IDCardData:
    cid: str = ""
    th_fullname: str = ""
    en_fullname: str = ""
    dob: str = ""
    gender: str = ""
    issuer: str = ""
    issue_date: str = ""
    expire_date: str = ""
    address: str = ""
    photo_bytes: Optional[bytearray] = None


class SmartCardReader:

    def __init__(self, reader):
        self.reader = reader

    def _get_data_with_get_response(self, conn: SmartCardConnection, command_apdu: List[int]) -> List[int]:
        _, sw1, sw2 = conn.transmit(command_apdu)
        expected_len = command_apdu[-1]

        if [sw1, sw2] == SW_SUCCESS:
            pass
        elif sw1 == 0x61:
            expected_len = sw2
        else:
            raise SmartCardError(f"Command failed ({toHexString(command_apdu)}): {sw1:02X} {sw2:02X}")

        get_response_apdu = conn.get_response_apdu_prefix + [expected_len]
        data, sw1, sw2 = conn.transmit(get_response_apdu)

        if [sw1, sw2] != SW_SUCCESS:
            raise SmartCardError(f"GET RESPONSE failed ({toHexString(get_response_apdu)}): {sw1:02X} {sw2:02X}")

        return data

    def _read_field(self, conn: SmartCardConnection, cmd: APDUCommand) -> str:
        data = self._get_data_with_get_response(conn, cmd.ins)
        return cmd.decoder(data)

    def _read_photo(self, conn: SmartCardConnection, segments: int = 20) -> bytearray:
        photo_data = bytearray()

        for i in range(1, segments + 1):
            p1_byte = i & 0xFF
            p2_byte = (0x7C - i) & 0xFF
            current_cmd = [0x80, 0xB0, p1_byte, p2_byte, 0x02, 0x00, 0xFF]

            try:
                segment_data = self._get_data_with_get_response(conn, current_cmd)
                photo_data.extend(segment_data)
            except SmartCardError as e:
                break

        if len(photo_data) < 1024:
            return None

        return photo_data

    def read_card(self) -> IDCardData:
        conn = None
        try:
            conn = SmartCardConnection(self.reader.createConnection())
            conn.connect()

            # 1. Select Applet
            apdu = APDU_SELECT_COMMAND + APDU_APPLET_ID
            _, sw1, sw2 = conn.transmit(apdu)

            if [sw1, sw2] == SW_SUCCESS:
                pass

            elif sw1 == 0x61:
                get_response_apdu = conn.get_response_apdu_prefix + [sw2]
                _, res_sw1, res_sw2 = conn.transmit(get_response_apdu)

                if [res_sw1, res_sw2] != SW_SUCCESS:
                    raise SmartCardError(f"Failed to select applet (GET RESPONSE failed): {res_sw1:02X} {res_sw2:02X}")

            else:
                raise SmartCardError(f"Failed to select applet: {sw1:02X} {sw2:02X}")

            # 2. Read Data Fields
            commands = [
                APDUCommand([0x80, 0xB0, 0x00, 0x04, 0x02, 0x00, 0x0D], "cid"),
                APDUCommand([0x80, 0xB0, 0x00, 0x11, 0x02, 0x00, 0x64], "th_fullname"),
                APDUCommand([0x80, 0xB0, 0x00, 0x75, 0x02, 0x00, 0x64], "en_fullname"),
                APDUCommand([0x80, 0xB0, 0x00, 0xD9, 0x02, 0x00, 0x08], "dob"),
                APDUCommand([0x80, 0xB0, 0x00, 0xE1, 0x02, 0x00, 0x01], "gender"),
                APDUCommand([0x80, 0xB0, 0x00, 0xF6, 0x02, 0x00, 0x64], "issuer"),
                APDUCommand([0x80, 0xB0, 0x01, 0x67, 0x02, 0x00, 0x08], "issue_date"),
                APDUCommand([0x80, 0xB0, 0x01, 0x6F, 0x02, 0x00, 0x08], "expire_date"),
                APDUCommand([0x80, 0xB0, 0x15, 0x79, 0x02, 0x00, 0x64], "address"),
            ]

            card_data = IDCardData()
            for cmd in commands:
                result = self._read_field(conn, cmd)
                setattr(card_data, cmd.label, result)

            # 3. Read Photo
            card_data.photo_bytes = self._read_photo(conn)

            return card_data

        finally:
            if conn:
                conn.disconnect()


# --- PYQT6 WORKER AND MAIN WINDOW ---

class ReaderWorker(QObject):
    finished = pyqtSignal(IDCardData)
    error = pyqtSignal(str)

    def __init__(self, reader):
        super().__init__()
        self.reader = reader

    def run(self):
        try:
            reader_instance = SmartCardReader(self.reader)
            data = reader_instance.read_card()
            self.finished.emit(data)
        except SmartCardError as e:
            self.error.emit(f"Smart Card Error: {e}")
        except Exception as e:
            self.error.emit(f"An unexpected error occurred: {e}")


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Thai ID Card Scanner")
        self.setGeometry(100, 100, 850, 650)  # ปรับขนาดให้ใหญ่ขึ้นเล็กน้อย

        self.card_data: IDCardData = IDCardData()
        self.photo_bytes: Optional[bytearray] = None
        self.init_ui()

    def init_ui(self):
        # Central Widget and Main Layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # ใช้ Grid Layout เพื่อความยืดหยุ่นและการจัดวางที่ดีขึ้น
        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(20)  # เพิ่มระยะห่างระหว่าง Panel

        # --- Left Panel: Photo and Buttons ---
        left_panel_widget = QWidget()
        left_panel_widget.setObjectName("LeftPanelWidget")
        left_panel = QVBoxLayout(left_panel_widget)
        left_panel.setAlignment(Qt.AlignmentFlag.AlignTop)

        # Photo Display
        self.photo_label = QLabel("Waiting for Scan...")
        self.photo_label.setObjectName("PhotoLabel")
        self.photo_label.setFixedSize(250, 310)  # ปรับขนาดรูปให้ใหญ่ขึ้น
        self.photo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Header สำหรับรูป
        photo_header = QLabel("Citizen Photo")
        photo_header.setObjectName("HeaderLabel")
        photo_header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        left_panel.addWidget(photo_header)

        left_panel.addWidget(self.photo_label, alignment=Qt.AlignmentFlag.AlignCenter)
        left_panel.addSpacing(20)

        # Scan Button
        self.scan_button = QPushButton("SCAN CARD")
        left_panel.addWidget(self.scan_button)

        # Save Photo Button
        self.save_button = QPushButton("SAVE PHOTO (JPEG)")
        self.save_button.setEnabled(False)
        left_panel.addWidget(self.save_button)

        left_panel.addStretch(1)
        main_layout.addWidget(left_panel_widget)

        # --- Right Panel: Data Fields ---
        right_panel_widget = QWidget()
        right_panel_widget.setObjectName("RightPanelWidget")
        data_panel = QVBoxLayout(right_panel_widget)

        # Header สำหรับข้อมูล
        data_header = QLabel("THAI NATIONAL ID CARD DATA")
        data_header.setObjectName("HeaderLabel")
        data_header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        data_panel.addWidget(data_header)
        data_panel.addSpacing(10)

        self.data_fields = {}
        fields = [
            ("CID", "เลขบัตรประชาชน"),
            ("TH Fullname", "ชื่อ-สกุล (ไทย)"),
            ("EN Fullname", "ชื่อ-สกุล (อังกฤษ)"),
            ("Date of birth", "วันเกิด (วว/ดด/ปป)"),
            ("Gender", "เพศ"),
            ("Issue Date", "วันที่ออกบัตร"),
            ("Expire Date", "วันหมดอายุ"),
            ("Card Issuer", "ผู้ออกบัตร"),
            ("Address", "ที่อยู่"),
        ]

        # Create Labels and LineEdits
        for field_key, field_label in fields:
            h_layout = QHBoxLayout()
            label = QLabel(field_label + ":")
            label.setFixedWidth(150)
            label.setFont(QFont('Segoe UI', 10, QFont.Weight.Bold))  # เน้น Label

            if field_key == "Address":
                edit = QTextEdit()
                edit.setReadOnly(True)
                edit.setFixedHeight(70)
            else:
                edit = QLineEdit()
                edit.setReadOnly(True)

            self.data_fields[field_key] = edit

            h_layout.addWidget(label)
            h_layout.addWidget(edit)
            data_panel.addLayout(h_layout)

        data_panel.addStretch(1)
        main_layout.addWidget(right_panel_widget)

        # Connect signals
        self.scan_button.clicked.connect(self.start_scan)
        self.save_button.clicked.connect(self.save_photo)

    def start_scan(self):
        self.scan_button.setEnabled(False)
        self.scan_button.setText("Scanning... (Please Wait)")
        self.save_button.setEnabled(False)
        self.clear_fields()

        try:
            reader_list = readrse()
            if not reader_list:
                raise SmartCardError("No smartcard readers found. Please plug in the reader.")

            TARGET_READER_NAMES = ['TRK2700RB', 'IDENTIV', 'SCR', 'CCID']
            selected_reader = None
            for reader in reader_list:
                reader_name = str(reader).upper()
                if any(name in reader_name for name in TARGET_READER_NAMES):
                    selected_reader = reader
                    break

            if selected_reader is None:
                selected_reader = reader_list[0]

            print(f"Using reader: {str(selected_reader)}")

            self.thread = QThread()
            self.worker = ReaderWorker(selected_reader)
            self.worker.moveToThread(self.thread)

            self.thread.started.connect(self.worker.run)
            self.worker.finished.connect(self.on_scan_finished)
            self.worker.error.connect(self.on_scan_error)
            self.worker.finished.connect(self.thread.quit)
            self.worker.error.connect(self.thread.quit)
            self.thread.start()

        except SmartCardError as e:
            self.on_scan_error(str(e))
        except Exception as e:
            self.on_scan_error(f"Reader initialization error: {e}")

    def clear_fields(self):
        for key in self.data_fields:
            field_widget = self.data_fields[key]
            if isinstance(field_widget, QLineEdit):
                field_widget.clear()
            elif isinstance(field_widget, QTextEdit):
                field_widget.clear()

        self.photo_label.setText("Waiting for Scan...")
        self.photo_label.setPixmap(QPixmap())
        self.photo_bytes = None

    def on_scan_finished(self, data: IDCardData):
        self.card_data = data

        self.data_fields["CID"].setText(data.cid)
        self.data_fields["TH Fullname"].setText(data.th_fullname)
        self.data_fields["EN Fullname"].setText(data.en_fullname)

        # *** DATE FORMATTING: วันเกิด ***
        self.data_fields["Date of birth"].setText(format_date(data.dob))

        # *** GENDER MAPPING ***
        gender_code = data.gender.strip()
        gender_text = ""
        if gender_code == "1":
            gender_text = "ชาย"
        elif gender_code == "2":
            gender_text = "หญิง"
        else:
            gender_text = f"ไม่ระบุ ({gender_code})"

        self.data_fields["Gender"].setText(gender_text)

        self.data_fields["Issue Date"].setText(format_date(data.issue_date))
        self.data_fields["Expire Date"].setText(format_date(data.expire_date))

        self.data_fields["Card Issuer"].setText(data.issuer)
        self.data_fields["Address"].setText(data.address)

        if data.photo_bytes:
            self.photo_bytes = data.photo_bytes
            pixmap = QPixmap()
            if pixmap.loadFromData(bytes(data.photo_bytes), "JPG"):
                self.photo_label.setPixmap(
                    pixmap.scaled(self.photo_label.size(), Qt.AspectRatioMode.KeepAspectRatio,
                                  Qt.TransformationMode.SmoothTransformation)
                )
                self.save_button.setEnabled(True)
            else:
                self.photo_label.setText("Error: Cannot display photo data (Invalid JPEG?)")
                self.save_button.setEnabled(False)
        else:
            self.photo_label.setText("No Photo Found")
            self.save_button.setEnabled(False)

        self.scan_button.setEnabled(True)
        self.scan_button.setText("SCAN CARD")
        QMessageBox.information(self, "Success", "Card data read successfully!")

    def on_scan_error(self, message: str):
        self.scan_button.setEnabled(True)
        self.scan_button.setText("SCAN CARD")
        QMessageBox.critical(self, "Error", message)

    def save_photo(self):
        if not self.photo_bytes:
            QMessageBox.warning(self, "Warning", "No photo data to save.")
            return

        cid_filename = self.card_data.cid if self.card_data.cid else "photo"

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Photo",
            f"{cid_filename}.jpg",
            "JPEG Files (*.jpg);;All Files (*)"
        )

        if file_path:
            try:
                Path(file_path).write_bytes(self.photo_bytes)
                QMessageBox.information(self, "Success", f"Photo saved to {file_path}")
            except IOError as e:
                QMessageBox.critical(self, "Error", f"Failed to save file: {e}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    load_stylesheet(app)  # โหลด QSS ที่นี่
    window = MainWindow()
    window.show()
    sys.exit(app.exec())