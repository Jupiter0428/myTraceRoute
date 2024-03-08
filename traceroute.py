from PyQt5 import QtCore, QtGui, QtWidgets
import sys
from PyQt5.QtWidgets import *
from ping3 import ping
import requests
import re
from scapy.layers.inet import IP
from scapy.layers.inet import ICMP
from scapy.all import sr1
from ipaddress import ip_address

column_name = {0: "Hop",
               1: "IP",
               2: "域名",
               3: "国家",
               4: "城市",
               5: "ASN",
               6: "组织",
               7: "延迟"}


def getGeoInfo(ip):
    url = ''
    data = {
        "ipaddr": ip,
        "lang": "zh-CN"
    }
    r = requests.post(url, json=data)
    result = r.json()
    return result


def check_ip(ip):
    compile_ip = re.compile('^(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[1-9])\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)$')
    if compile_ip.match(ip):
        return True
    else:
        return False


def pingHost(ip):
    response = ping(ip)
    if response is not None:
        delay = int(response * 1000)
        return delay
    return 0


class Ui_Form(QWidget):
    def __init__(self):
        super().__init__()
        self.tableWidget = QtWidgets.QTableWidget(self)
        self.lineEdit = QtWidgets.QLineEdit(self)
        self.lineEdit_2 = QtWidgets.QLineEdit(self)
        self.label = QtWidgets.QLabel(self)
        self.label_2 = QtWidgets.QLabel(self)
        self.pushButton = QtWidgets.QPushButton(self)
        self.gridLayout = QtWidgets.QGridLayout(self)
        self.setupUi()

    def setupUi(self):
        self.setObjectName("Form")
        self.resize(853, 578)
        self.setToolTipDuration(-2)
        self.setStyleSheet("")
        self.gridLayout.setObjectName("gridLayout")
        font = QtGui.QFont()
        font.setFamily("宋体")
        font.setPointSize(14)
        font.setKerning(False)
        self.pushButton.setFont(font)
        self.pushButton.setStyleSheet("background:rgb(189, 189, 255)")
        self.pushButton.setObjectName("pushButton")
        self.gridLayout.addWidget(self.pushButton, 0, 6, 1, 1)
        font = QtGui.QFont()
        font.setFamily("宋体")
        font.setPointSize(14)
        self.label_2.setFont(font)
        self.label_2.setObjectName("label_2")
        self.gridLayout.addWidget(self.label_2, 0, 4, 1, 1)
        self.lineEdit.setObjectName("lineEdit")
        self.gridLayout.addWidget(self.lineEdit, 0, 3, 1, 1)
        font = QtGui.QFont()
        font.setFamily("宋体")
        font.setPointSize(14)
        self.label.setFont(font)
        self.label.setObjectName("label")
        self.gridLayout.addWidget(self.label, 0, 2, 1, 1)
        self.lineEdit_2.setMaximumSize(QtCore.QSize(60, 16777215))
        self.lineEdit_2.setObjectName("lineEdit_2")
        self.gridLayout.addWidget(self.lineEdit_2, 0, 5, 1, 1)
        self.tableWidget.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)  # 设置不可编辑
        self.tableWidget.verticalHeader().setVisible(False)  # 隐藏行号
        self.tableWidget.setObjectName("tableWidget")
        self.tableWidget.setColumnCount(8)
        self.tableWidget.setRowCount(0)

        for i in range(0, 8):
            self.tableWidget.setHorizontalHeaderItem(i, QtWidgets.QTableWidgetItem())

        self.gridLayout.addWidget(self.tableWidget, 2, 2, 1, 5)

        self.retranslateUi()
        QtCore.QMetaObject.connectSlotsByName(self)
        self.pushButton.clicked.connect(self.traceRoute)
        self.show()

    def retranslateUi(self):
        _translate = QtCore.QCoreApplication.translate
        self.setWindowTitle(_translate("Form", "Traceroute"))
        self.pushButton.setText(_translate("Form", "查询"))
        self.label_2.setText(_translate("Form", "最大跳数："))
        self.label.setText(_translate("Form", "IP地址："))
        for i in column_name:
            item = self.tableWidget.horizontalHeaderItem(i)
            item.setText(_translate("Form", column_name[i]))

    # 清理表格数据
    def cleanTable(self):
        row = self.tableWidget.rowCount()
        if row > 0:
            self.tableWidget.clearContents()  # 清除表格中的单元格内容
            self.tableWidget.setRowCount(0)  # 清除所有行

    # 外网ip
    def insertTable_extranet(self, ttl, ip, info, delay):
        row = self.tableWidget.rowCount()
        self.tableWidget.insertRow(row)
        self.tableWidget.setItem(row, 0, QtWidgets.QTableWidgetItem(str(ttl)))
        self.tableWidget.setItem(row, 1, QtWidgets.QTableWidgetItem(ip))
        self.tableWidget.setItem(row, 2, QtWidgets.QTableWidgetItem(';'.join(info['domains'])))
        self.tableWidget.setItem(row, 3, QtWidgets.QTableWidgetItem(info['country']))
        self.tableWidget.setItem(row, 4, QtWidgets.QTableWidgetItem(info['city']))
        self.tableWidget.setItem(row, 5, QtWidgets.QTableWidgetItem(info['asn']))
        self.tableWidget.setItem(row, 6, QtWidgets.QTableWidgetItem(info['org']))
        self.tableWidget.setItem(row, 7, QtWidgets.QTableWidgetItem(f"{delay}ms"))
        QApplication.processEvents()  # 刷新页面

    # 内网ip
    def insertTable_intranet(self, ttl, ip, delay):
        row = self.tableWidget.rowCount()
        self.tableWidget.insertRow(row)
        self.tableWidget.setItem(row, 0, QtWidgets.QTableWidgetItem(str(ttl)))
        self.tableWidget.setItem(row, 1, QtWidgets.QTableWidgetItem(ip))
        self.tableWidget.setItem(row, 7, QtWidgets.QTableWidgetItem(f"{delay}ms"))
        QApplication.processEvents()  # 刷新页面

    # 无响应ip
    def insertTable_empty(self, ttl, ip):
        row = self.tableWidget.rowCount()
        self.tableWidget.insertRow(row)
        self.tableWidget.setItem(row, 0, QtWidgets.QTableWidgetItem(str(ttl)))
        self.tableWidget.setItem(row, 1, QtWidgets.QTableWidgetItem(ip))
        QApplication.processEvents()  # 刷新页面

    def traceRoute(self):
        self.cleanTable()

        dest = self.lineEdit.text()  # 获取目标地址
        if check_ip(dest) is not True:
            return

        max_hops = self.lineEdit_2.text()  # 获取最大跳数
        if max_hops.isdigit() is not True:
            return
        else:
            max_hops = int(max_hops)

        ttl = 1
        while True:
            packet = IP(dst=dest, ttl=ttl) / ICMP()
            reply = sr1(packet, verbose=0, timeout=1)

            if reply is None:
                # print(f"{ttl}. *")
                self.insertTable_empty(ttl, "*")

            elif reply.type == 0:
                delay = pingHost(reply.src)
                if ip_address(reply.src.strip()).is_private:
                    self.insertTable_intranet(ttl, reply.src, delay)
                else:
                    try:
                        geoipinfo = getGeoInfo(reply.src)
                        self.insertTable_extranet(ttl, reply.src, geoipinfo, delay)
                    except:
                        self.insertTable_intranet(ttl, reply.src, delay)
                break
            else:
                delay = pingHost(reply.src)
                if ip_address(reply.src.strip()).is_private:
                    self.insertTable_intranet(ttl, reply.src, delay)
                else:
                    try:
                        geoipinfo = getGeoInfo(reply.src)
                        self.insertTable_extranet(ttl, reply.src, geoipinfo, delay)
                    except:
                        self.insertTable_intranet(ttl, reply.src, delay)

            if ttl == max_hops:
                break
            else:
                ttl += 1


if __name__ == "__main__":
    app = QApplication(sys.argv)
    w = Ui_Form()
    sys.exit(app.exec_())