#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <getopt.h>
#include <net/if.h>
#include <string.h>
#include <QDebug>

#define FW_CDEV_NAME "/dev/myfw"
#define IF_NAME "eth0"
#define IF_NAME_OUT "eth1"

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent),
                                          ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    fd = open(FW_CDEV_NAME, O_RDWR);
    if (fd <= 0)
    {
        warningBox("Error with your character device: " + QString(FW_CDEV_NAME));
    }

    //my init
    initCopyRight();
    initFirewallTable();
    initLinkTable();
    initNatTable();

    link_timer = new QTimer();
    connect(link_timer, SIGNAL(timeout()), this, SLOT(refreshLinkTable()));
    link_timer->start(1 * 1000);

    log_timer = new QTimer();
    connect(log_timer, SIGNAL(timeout()), this, SLOT(updateLogFile()));
    log_timer->start(10 * 1000);
}

void MainWindow::initCopyRight()
{
    //statusBar初始化
    statusLabel = new QLabel();
    statusLabel->setMinimumSize(200, 20);
    statusLabel->setAlignment(Qt::AlignLeft);
    ui->statusBar->addWidget(statusLabel);
}

/*QTableWidget初始化*/
void MainWindow::initFirewallTable()
{
    QStringList header;

    ui->tableWidget_firewall->setColumnCount(7);
    header << "source ip"
           << "dest ip"
           << "S port"
           << "D port"
           << "protocol"
           << "action"
           << "log";
    ui->tableWidget_firewall->setHorizontalHeaderLabels(header);
    ui->tableWidget_firewall->setEditTriggers(QAbstractItemView::NoEditTriggers);   // set readonly
    ui->tableWidget_firewall->setSelectionMode(QAbstractItemView::SingleSelection); //设置选择的模式为单选择
    ui->tableWidget_firewall->setSelectionBehavior(QAbstractItemView::SelectRows);  //设置选择行为时每次选择一行
    ui->tableWidget_firewall->horizontalHeader()->setStretchLastSection(true);

    ui->tableWidget_firewall->setColumnWidth(0, 160);
    ui->tableWidget_firewall->setColumnWidth(1, 160);
    ui->tableWidget_firewall->setColumnWidth(2, 60);
    ui->tableWidget_firewall->setColumnWidth(3, 60);
    ui->tableWidget_firewall->setColumnWidth(4, 80);
    ui->tableWidget_firewall->setColumnWidth(5, 60);
    ui->tableWidget_firewall->setColumnWidth(6, 60);

    rulesFilename = "./rules.dat";
    //rules.dat文件中每一条规则的形式: sip:dip:sport:dport:protocolnumber:smask:dmask:0:0\n
    //读取rules.dat中保存的规则
    QFile file(rulesFilename);
    QString line;

    Node item;
    //判断rules.dat文件是否存在，若不存在，则直接跳过此步骤
    if (QFileInfo::exists(rulesFilename) && file.open(QFile::ReadOnly))
    {
        item.next = NULL;
        while (!file.atEnd())
        {
            line = QString::fromLocal8Bit(file.readLine().data()); //在文件中读取一行，char*，转为QString
            item.sip = line.section(":", 0, 0).trimmed().toUInt(); //section，以：分割，返回从第0个：开始到第1个：中间的字符串（即第1个：之前的字符串，第0个：表示字符串起始位置）
            item.dip = line.section(":", 1, 1).trimmed().toUInt();
            item.sport = line.section(":", 2, 2).trimmed().toUShort();
            item.dport = line.section(":", 3, 3).trimmed().toUShort();
            item.protocol = line.section(":", 4, 4).trimmed().toUShort();
            item.sMask = line.section(":", 5, 5).trimmed().toShort();
            item.dMask = line.section(":", 6, 6).trimmed().toShort();

            if (line.section(":", 7, 7).trimmed().toUShort() == 1)
            {
                item.isPermit = true;
            }
            else
            {
                item.isPermit = false;
            }

            if (line.section(":", 8, 8).trimmed().toUShort() == 1)
            {
                item.isLog = true;
            }
            else
            {
                item.isLog = false;
            }

            ruleList.push_back(item);
        }
        file.close();
    }

    //在UI中显示规则，并向内核传递规则
    for (int i = 0, len = ruleList.length(); i < len; i++)
    {
        addFirewallRuleToTable(ruleList[i], i);
        ioctl(fd, FW_ADD_RULE, &ruleList[i]);
    }
}

/*向UI中添加一条规则*/
void MainWindow::addFirewallRuleToTable(Node item, unsigned int i)
{
    QString sip;
    QString dip;
    QString protocol;

    sip = getStringIPAddr(item.sip);

    protocol = getProtocolName(item.protocol);

    //例如192.168.1.1/24
    if (item.sMask > 0)
    {
        sip += QString("/") + QString::number(item.sMask);
    }

    dip = getStringIPAddr(item.dip);
    if (item.dMask > 0)
    {
        dip += QString("/") + QString::number(item.dMask);
    }

    //QTableList行数不够
    unsigned int len = ui->tableWidget_firewall->rowCount();
    if (len == i)
    {
        ui->tableWidget_firewall->setRowCount(i + 1);
    }

    //把规则画上去
    ui->tableWidget_firewall->setItem(i, 0, new QTableWidgetItem(sip));
    ui->tableWidget_firewall->setItem(i, 1, new QTableWidgetItem(dip));
    if (item.sport)
    {
        ui->tableWidget_firewall->setItem(i, 2, new QTableWidgetItem(QString::number(item.sport)));
    }
    else
    {
        ui->tableWidget_firewall->setItem(i, 2, new QTableWidgetItem("ANY"));
    }
    if (item.dport)
    {
        ui->tableWidget_firewall->setItem(i, 3, new QTableWidgetItem(QString::number(item.dport)));
    }
    else
    {
        ui->tableWidget_firewall->setItem(i, 3, new QTableWidgetItem("ANY"));
    }
    ui->tableWidget_firewall->setItem(i, 4, new QTableWidgetItem(protocol));

    if (item.isPermit)
    {
        ui->tableWidget_firewall->setItem(i, 5, new QTableWidgetItem("Permit"));
    }
    else
    {
        ui->tableWidget_firewall->setItem(i, 5, new QTableWidgetItem("Reject"));
    }

    if (item.isLog)
    {
        ui->tableWidget_firewall->setItem(i, 6, new QTableWidgetItem("true"));
    }
    else
    {
        ui->tableWidget_firewall->setItem(i, 6, new QTableWidgetItem("false"));
    }
}

/*更新规则文件*/
void MainWindow::refreshDefaultRuleFile()
{
    QFile file(rulesFilename);
    if (file.open(QFile::WriteOnly))
    {
        QTextStream out(&file);
        QString str;
        Node item;
        for (int i = 0, len = ruleList.length(); i < len; i++)
        {
            item = ruleList[i];
            QString str = QString::number(item.sip) + ":" + QString::number(item.dip) + ":";
            str += QString::number(item.sport) + ":";
            str += QString::number(item.dport) + ":";
            str += QString::number(item.protocol) + ":";
            str += QString::number(item.sMask) + ":";
            str += QString::number(item.dMask) + ":";
            if (item.isPermit)
            {
                str += "1:";
            }
            else
            {
                str += "0:";
            }

            if (item.isLog)
            {
                str += "1\n";
            }
            else
            {
                str += "0\n";
            }
            out << str;
        }
        file.close();
    }
}

/*增加规则按钮函数*/
void MainWindow::on_add_firewall_rule_Btn_clicked()
{

    Node item;
    QString sIPstr = ui->sourceIPInput->text().trimmed();
    QString dIPstr = ui->destIPInput->text().trimmed();

    //检测IP是否合法
    if (!checkIP(sIPstr) || !checkIP(dIPstr))
    {
        warningBox("IP is not right!");
        return;
    }

    //检测端口是否合法
    QString sPortStr = ui->sourcePortInput->text().trimmed();
    QString dPortStr = ui->destPortInput->text().trimmed();
    if (!checkPort(sPortStr) || !checkPort(dPortStr))
    {
        warningBox("Port is not right!");
        return;
    }

    //IP处理
    char *csip = sIPstr.toLocal8Bit().data(); //QString to char*
    item.sip = inet_addr(csip);               //char* to uint
    item.sport = getPort(sPortStr);           //QString to uint

    //端口处理
    char *cdip = dIPstr.toLocal8Bit().data();
    item.dip = inet_addr(cdip);
    item.dport = getPort(dPortStr);

    //获取协议号，0表示任意协议
    QString protocol = ui->protocolComboBox->currentText().trimmed();
    item.protocol = getProtocolNumber(protocol.toLocal8Bit().data());

    //ICMP报文的端口设置为0
    if (protocol == "ICMP")
    {
        item.sport = 0;
        item.dport = 0;
    }

    //获取掩码
    item.sMask = getSubNetMaskNumber(sIPstr);
    item.dMask = getSubNetMaskNumber(dIPstr);

    //通过或丢弃
    if (ui->buttonGroup->checkedButton()->objectName().trimmed() == "permit")
    {
        item.isPermit = true;
    }
    else
    {
        item.isPermit = false;
    }

    //是否记录日志
    if (ui->writeLogChecked->isChecked())
    {
        item.isLog = true;
    }
    else
    {
        item.isLog = false;
    }

    //相同的规则不需要重复添加
    bool isExisted = false;
    for (int i = 0, len = ruleList.length(); i < len; i++)
    {
        if (ruleList[i].sip != item.sip || ruleList[i].dip != item.dip)
        {
            continue;
        }

        if (ruleList[i].protocol != item.protocol)
        {
            continue;
        }

        //ICMP无需检查端口
        if (item.protocol == IPPROTO_ICMP)
        {
            isExisted = true;
            break;
        }

        if (ruleList[i].sport != item.sport || ruleList[i].dport != item.dport)
        {
            continue;
        }

        isExisted = true;
        break;
    }

    if (isExisted)
    {
        warningBox("This rule already exists!");
        return;
    }

    //QVector添加规则
    ruleList.append(item);

    //UI展示规则
    unsigned int len = ruleList.length();
    addFirewallRuleToTable(item, len - 1);

    //规则发送至内核
    ioctl(fd, FW_ADD_RULE, &item);
}

/*删除规则*/
void MainWindow::on_delete_firewall_rule_Btn_clicked()
{

    //QTableList长度是否大于0
    int len = ruleList.length();
    if (len <= 0)
    {
        warningBox("Nothing to delete.");
        return;
    }

    //获取当前行
    int row = -1;
    row = ui->tableWidget_firewall->currentRow();
    if (row < 0)
    {
        warningBox("Please select a row to delete.");
        return;
    }

    //当前行越界
    if (row >= len)
    {
        // out of range
        return;
    }

    //询问是否确定删除
    bool reply = questionBox("Delete checked", "Delete the selected row?", "Yes", "No");
    if (!reply)
    {
        return;
    }

    //UI删除
    ui->tableWidget_firewall->removeRow(row);

    //内核规则删除
    ioctl(fd, FW_DEL_RULE, &ruleList[row]);

    //QVector删除
    ruleList.remove(row);
}

/*清空规则*/
void MainWindow::on_clear_firewall_rule_Btn_clicked()
{

    //询问是否确定清空
    bool reply = questionBox("Clear check", "Clear all the rules ?", "Yes", "No");
    if (!reply)
    {
        return;
    }

    //QVector清空
    ruleList.clear();

    //UI清空
    ui->tableWidget_firewall->clearContents();
    ui->tableWidget_firewall->setRowCount(0);

    //内核规则清空
    //Node item = {0,0,0,0,0,0,0,false,false,NULL};
    //qDebug("I will send the signal!\n");
    ioctl(fd, FW_CLEAR_RULE, NULL);
    //qDebug("complete!\n");
}

void MainWindow::on_change_default_action_Btn_clicked()
{
    int dr;
    if (ui->buttonGroup_2->checkedButton()->objectName().trimmed() == "D_PERMIT")
    {
        dr = 0;
    }
    else
    {
        dr = 1;
    }
    ioctl(fd, FW_SET_DEFAULT_RULE, &dr);
}

/*是否重写文件*/
void MainWindow::on_rewrite_default_firewall_rule_Btn_clicked()
{
    bool reply = questionBox("Rewrite rules file check", "Rewrite the defaule rules file with current table?", "Yes", "No");
    if (!reply)
    {
        return;
    }
    refreshDefaultRuleFile();
}

void MainWindow::initLinkTable()
{
    QStringList header;

    ui->tableWidget_link->setColumnCount(5);
    header << "source ip"
           << "S port"
           << "dest ip"
           << "D port"
           << "lifetime";
    ui->tableWidget_link->setHorizontalHeaderLabels(header);
    ui->tableWidget_link->setEditTriggers(QAbstractItemView::NoEditTriggers);   // set readonly
    ui->tableWidget_link->setSelectionMode(QAbstractItemView::SingleSelection); //设置选择的模式为单选择
    ui->tableWidget_link->setSelectionBehavior(QAbstractItemView::SelectRows);  //设置选择行为时每次选择一行
    ui->tableWidget_link->horizontalHeader()->setStretchLastSection(true);

    ui->tableWidget_link->setColumnWidth(0, 160);
    ui->tableWidget_link->setColumnWidth(1, 60);
    ui->tableWidget_link->setColumnWidth(2, 160);
    ui->tableWidget_link->setColumnWidth(3, 60);
    ui->tableWidget_link->setColumnWidth(4, 60);
}

void MainWindow::addLinkRuleToTable(LinkNode item, unsigned int i)
{
    QString sip;
    QString dip;

    sip = getStringIPAddr(item.sip);
    dip = getStringIPAddr(item.dip);

    //QTableList行数不够
    unsigned int len = ui->tableWidget_link->rowCount();
    if (len == i)
    {
        ui->tableWidget_link->setRowCount(i + 1);
    }

    //把规则画上去
    ui->tableWidget_link->setItem(i, 0, new QTableWidgetItem(sip));

    if (item.sport)
    {
        ui->tableWidget_link->setItem(i, 1, new QTableWidgetItem(QString::number(item.sport)));
    }
    else
    {
        ui->tableWidget_link->setItem(i, 1, new QTableWidgetItem("ANY"));
    }

    ui->tableWidget_link->setItem(i, 2, new QTableWidgetItem(dip));

    if (item.dport)
    {
        ui->tableWidget_link->setItem(i, 3, new QTableWidgetItem(QString::number(item.dport)));
    }
    else
    {
        ui->tableWidget_link->setItem(i, 3, new QTableWidgetItem("ANY"));
    }

    ui->tableWidget_link->setItem(i, 4, new QTableWidgetItem(QString::number(item.lifetime)));
}

/*refresh the tableWidget_link*/
void MainWindow::refreshLinkTable()
{
    ui->tableWidget_link->clearContents();
    ui->tableWidget_link->setRowCount(0);
    unsigned int link_num = -1;
    ioctl(fd, FW_GET_LINK_NUM, &link_num);

    if (link_num < 0)
        return;

    LinkNode *link_list = new LinkNode[link_num + 50];
    memset(link_list, 0, (link_num + 50) * sizeof(LinkNode));
    ioctl(fd, FW_GET_LINK_LIST, link_list);

    for (unsigned int i = 0; i < link_num + 50; i++)
    {
        if (link_list[i].dip == 0)
            break;
        addLinkRuleToTable(link_list[i], i);
    }
    delete link_list;
}

/*update log file*/
void MainWindow::updateLogFile()
{
    QFile logfile("/var/log/myfilter");
    if (!logfile.open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text))
    {
        qDebug() << "something wrong with the log file!\n";
        return;
    }
    QTextStream logstream(&logfile);

    int log_num = -1;
    ioctl(fd, FW_GET_LOG_NUM, &log_num);

    if (log_num <= 0)
        return;

    //qDebug()<<"log num is"<<log_num<<"\n";
    LogNode *log_list = new LogNode[log_num + 50];
    memset(log_list, 0, (log_num + 50) * sizeof(LogNode));
    //qDebug()<<"-------1-------\n";
    ioctl(fd, FW_GET_LOG_LIST, log_list);
    //qDebug()<<"-------2-------\n";
    QString str;

    for (int i = 0; i < log_num + 50; i++)
    {
        if (log_list[i].year == 0)
            break;
        str = QString("Time: ") + QString::number(log_list[i].year, 10) + QString("-") + QString::number(log_list[i].month, 10) +
              QString("-") + QString::number(log_list[i].day, 10) + QString(" ") + QString::number(log_list[i].hour, 10) + QString(":") +
              QString::number(log_list[i].minute, 10) + QString(":") + QString::number(log_list[i].second, 10) + QString("\n");

        str += QString("Package: sip: ") + getStringIPAddr(log_list[i].sip) + QString(" dip: ") + getStringIPAddr(log_list[i].dip) +
               QString(" sport: ") + getPortName(log_list[i].sport) + QString(" dport: ") + getPortName(log_list[i].dport) +
               QString(" protocol: ") + getProtocolName(log_list[i].protocol) + QString("\n");

        str += QString("Rule: sip: ") + getStringIPAddr(log_list[i].rule_sip) + QString(" dip: ") + getStringIPAddr(log_list[i].rule_dip) +
               QString(" sport: ") + getPortName(log_list[i].rule_sport) + QString(" dport: ") + getPortName(log_list[i].rule_dport) +
               QString(" protocol: ") + getProtocolName(log_list[i].rule_protocol);

        if (log_list[i].rule_permit)
            str += " action: permit\n\n";
        else
            str += " action: deny\n\n";

        logstream << str;
        //qDebug()<<str;
    }
    delete log_list;

    logfile.close();
}

void MainWindow::initNatTable()
{
    QStringList header;

    ui->tableWidget_nat->setColumnCount(4);
    header << "source ip"
           << "S port"
           << "nat ip"
           << "nat port";
    ui->tableWidget_nat->setHorizontalHeaderLabels(header);
    ui->tableWidget_nat->setEditTriggers(QAbstractItemView::NoEditTriggers);   // set readonly
    ui->tableWidget_nat->setSelectionMode(QAbstractItemView::SingleSelection); //设置选择的模式为单选择
    ui->tableWidget_nat->setSelectionBehavior(QAbstractItemView::SelectRows);  //设置选择行为时每次选择一
    ui->tableWidget_nat->horizontalHeader()->setStretchLastSection(true);

    ui->tableWidget_nat->setColumnWidth(0, 160);
    ui->tableWidget_nat->setColumnWidth(1, 60);
    ui->tableWidget_nat->setColumnWidth(2, 160);
    ui->tableWidget_nat->setColumnWidth(3, 60);
}

void MainWindow::on_nat_start_Btn_clicked()
{
    ui->nat_start_Btn->setEnabled(false);
    ui->nat_stop_Btn->setEnabled(true);

    char chostIP[32];
    char chostIP_out[32];
    char chostnetmask[32];
    getLocalIP(IF_NAME, (char *)chostIP, (char *)chostnetmask);
    qDebug() << chostIP;
    qDebug() << chostnetmask;

    hostIP = inet_addr(chostIP);
    hostnetmask = inet_addr(chostnetmask);

    getLocalIP(IF_NAME_OUT, (char *)chostIP_out, (char *)chostnetmask);
    qDebug() << chostIP_out;

    hostIP_out = inet_addr(chostIP_out);

    ioctl(fd, FW_SET_HOST_IP, &hostIP);
    ioctl(fd, FW_SET_HOST_NETMASK, &hostnetmask);
    ioctl(fd, FW_SET_HOST_IP_OUT, &hostIP_out);
    ioctl(fd, FW_START_NAT, NULL);

    nat_timer = new QTimer();
    connect(nat_timer, SIGNAL(timeout()), this, SLOT(refreshNatTable()));
    nat_timer->start(1 * 1000);
}

void MainWindow::on_nat_stop_Btn_clicked()
{
    ui->nat_start_Btn->setEnabled(true);
    ui->nat_stop_Btn->setEnabled(false);
    ioctl(fd, FW_STOP_NAT, NULL);
    ui->tableWidget_nat->clearContents();
    ui->tableWidget_nat->setRowCount(0);
    delete nat_timer;
}

void MainWindow::refreshNatTable()
{
    ui->tableWidget_nat->clearContents();
    ui->tableWidget_nat->setRowCount(0);
    int nat_num = -1;
    ioctl(fd, FW_GET_NAT_NUM, &nat_num);

    if (nat_num < 0)
    {
        return;
    }

    NatNode *nat_list = new NatNode[nat_num + 50];
    memset(nat_list, 0, (nat_num + 50) * sizeof(NatNode));
    ioctl(fd, FW_GET_NAT_LIST, nat_list);

    for (int i = 0; i < nat_num + 50; i++)
    {
        if (nat_list[i].dip == 0)
            break;
        addNatRuleToTable(nat_list[i], i);
    }
    delete nat_list;
}

void MainWindow::addNatRuleToTable(NatNode item, unsigned int i)
{
    QString sip;
    QString dip;

    sip = getStringIPAddr(item.sip);
    dip = getStringIPAddr(item.dip);

    //QTableList行数不够
    unsigned int len = ui->tableWidget_nat->rowCount();
    if (len == i)
    {
        ui->tableWidget_nat->setRowCount(i + 1);
    }

    //把规则画上去
    ui->tableWidget_nat->setItem(i, 0, new QTableWidgetItem(sip));

    if (item.sport)
    {
        ui->tableWidget_nat->setItem(i, 1, new QTableWidgetItem(QString::number(item.sport)));
    }
    else
    {
        ui->tableWidget_nat->setItem(i, 1, new QTableWidgetItem("ANY"));
    }

    ui->tableWidget_nat->setItem(i, 2, new QTableWidgetItem(dip));

    if (item.dport)
    {
        ui->tableWidget_nat->setItem(i, 3, new QTableWidgetItem(QString::number(item.dport)));
    }
    else
    {
        ui->tableWidget_nat->setItem(i, 3, new QTableWidgetItem("ANY"));
    }
}

MainWindow::~MainWindow()
{
    delete link_timer;
    delete log_timer;
    delete ui;
}

/*IP   char*转uint */
unsigned int MainWindow::inet_addr(char *str)
{
    int a, b, c, d;
    char arr[4];
    sscanf(str, "%d.%d.%d.%d", &a, &b, &c, &d);
    arr[0] = a;
    arr[1] = b;
    arr[2] = c;
    arr[3] = d;
    return *(unsigned int *)arr;
}

/*检查IP合法性*/
bool MainWindow::checkIP(QString ipstr)
{
    QRegExp reg("^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}(\\/[0-9]{1,2})?$");
    if (!reg.exactMatch(ipstr))
    {
        return false;
    }

    char *str = ipstr.toLocal8Bit().data();
    int a, b, c, d;
    sscanf(str, "%d.%d.%d.%d", &a, &b, &c, &d);

    //判断是否符合IP范围
    if (a < 0 || a > 255 || b < 0 || b > 255 || c < 0 || c > 255 || d < 0 || d > 255)
    {
        return false;
    }

    return true;
}

/*检查端口合法性*/
bool MainWindow::checkPort(QString portStr)
{
    QRegExp reg("^[0-9]{1,5}$");
    if (!reg.exactMatch(portStr))
    {
        return false;
    }

    // if use to ushort, maybe not true
    unsigned int t = portStr.toUInt();
    if (t >= MAX_PORT)
    {
        return false;
    }
    return true;
}

/*获取端口QString to ushort*/
unsigned short MainWindow::getPort(QString portStr)
{
    unsigned short port = portStr.toUShort();
    return port;
}

QString MainWindow::getPortName(unsigned int portNum)
{
    if (portNum == 0)
        return QString("ANY");
    else
        return QString::number(portNum);
}

/*获取子网掩码*/
unsigned short MainWindow::getSubNetMaskNumber(QString ipstr)
{
    QRegExp reg("^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\/((0-9)|([0-2][0-9])|(3[012]))$");
    if (!reg.exactMatch(ipstr))
    {
        return 0;
    }

    //获取子网掩码
    unsigned short mask = ipstr.mid(ipstr.lastIndexOf('/') + 1, -1).toUShort();

    //只允许8,16,24
    if (mask == 8 || mask == 16 || mask == 24)
    {
        return mask;
    }

    return 0;
}

/*获取协议号*/
unsigned short MainWindow::getProtocolNumber(QString protocol)
{

    //默认任意，即0
    unsigned short t = 0;
    if (QString::compare(protocol, "TCP") == 0)
    {
        t = IPPROTO_TCP;
    }
    else if (QString::compare(protocol, "UDP") == 0)
    {
        t = IPPROTO_UDP;
    }
    else if (QString::compare(protocol, "ICMP") == 0)
    {
        t = IPPROTO_ICMP;
    }
    return t;
}

/*协议号转协议名*/
QString MainWindow::getProtocolName(unsigned short protocolNumber)
{
    QString t = "ANY";
    switch (protocolNumber)
    {
    case IPPROTO_TCP:
        t = "TCP";
        break;
    case IPPROTO_UDP:
        t = "UDP";
        break;
    case IPPROTO_ICMP:
        t = "ICMP";
        break;
    default:

        break;
    }

    return t;
}

/*IP uint to QString*/
QString MainWindow::getStringIPAddr(unsigned int ip)
{
    unsigned int t = 0x000000ff;
    if (ip == 0)
    { // ANY
        return "ANY";
    }

    QString re;
    re.append(QString::number(ip & t)).append(".");
    re.append(QString::number((ip >> 8) & t)).append(".");
    re.append(QString::number((ip >> 16) & t)).append(".");
    re.append(QString::number((ip >> 24) & t)).append("\0");
    return re;
}

/*关闭事件*/
void MainWindow::closeEvent(QCloseEvent *event)
{
    bool reply = questionBox("Close check", "Close this program?", "Yes", "No");
    if (!reply)
    {
        event->ignore();
        return;
    }
    ::close(fd);
    event->accept();
}

/*警告消息*/
void MainWindow::warningBox(QString str)
{
    QMessageBox box(QMessageBox::Warning, "warning", str);
    box.setStandardButtons(QMessageBox::Ok);
    box.setButtonText(QMessageBox::Ok, QString("get it!"));
    box.exec();
}

/*询问消息*/
bool MainWindow::questionBox(QString title, QString msg, QString yesStr, QString noStr)
{
    QMessageBox reply(QMessageBox::Question, title, msg);
    reply.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
    reply.setButtonText(QMessageBox::Yes, QString(yesStr));
    reply.setButtonText(QMessageBox::No, QString(noStr));
    reply.setDefaultButton(QMessageBox::No);
    if (reply.exec() == QMessageBox::Yes)
    {
        return true;
    }
    else
    {
        return false;
    }
}

int getLocalIP(char *ifname, char *ip, char *netmask)
{
    char *temp = NULL;
    int inet_sock;
    struct ifreq ifr;

    inet_sock = socket(AF_INET, SOCK_DGRAM, 0);

    memset(ifr.ifr_name, 0, sizeof(ifr.ifr_name));
    memcpy(ifr.ifr_name, ifname, strlen(ifname));

    if (0 != ioctl(inet_sock, SIOCGIFADDR, &ifr))
    {
        perror("ioctl error");
        return -1;
    }

    temp = inet_ntoa(((struct sockaddr_in *)&(ifr.ifr_addr))->sin_addr);
    memcpy(ip, temp, strlen(temp));

    if (0 != ioctl(inet_sock, SIOCGIFNETMASK, &ifr))
    {
        perror("ioctl error");
        return -1;
    }

    temp = inet_ntoa(((struct sockaddr_in *)&(ifr.ifr_addr))->sin_addr);
    memcpy(netmask, temp, strlen(temp));

    close(inet_sock);

    return 0;
}
