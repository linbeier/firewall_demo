#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QIcon>
#include <QString>
#include <QAbstractButton>
#include <QRegExp>
#include <QMessageBox>
#include <QFile>
#include <QFileInfo>
#include <QTextStream>
#include <QTableWidget>
#include <QCloseEvent>
#include <QIcon>
#include <QLabel>
#include <QTimer>
/* ioctl commands */
#define FW_ADD_RULE 0
#define FW_DEL_RULE 1
#define FW_CLEAR_RULE 3
#define FW_SET_HOST_IP 4
#define FW_SET_HOST_NETMASK 5
#define FW_GET_LINK_NUM 6
#define FW_GET_LINK_LIST 7
#define FW_SET_DEFAULT_RULE 8
#define FW_GET_LOG_NUM 9
#define FW_GET_LOG_LIST 10
#define FW_START_NAT 11
#define FW_STOP_NAT 12
#define FW_GET_NAT_NUM 13
#define FW_GET_NAT_LIST 14
#define FW_SET_HOST_IP_OUT 15

/* some limit conditions */
#define MAX_RECORD 256 // max record number
#define MIN_PORT 0
#define MAX_PORT 0xFFFF

/* configure record */
struct Node
{
    unsigned int sip;
    unsigned int dip;
    unsigned short sport;
    unsigned short dport;
    unsigned short protocol;
    unsigned short sMask;
    unsigned short dMask;
    bool isPermit;
    bool isLog;
    struct Node *next; //单链表的指针域
};

struct LinkNode
{
    unsigned int sip;
    unsigned int dip;
    unsigned short sport;
    unsigned short dport;
    time_t start; //连接开始时的linux时间,超时1分钟,则断开连接
    unsigned int lifetime;
    struct LinkNode *next;
};

struct NatNode
{
    unsigned int sip;
    unsigned int dip;
    unsigned short sport;
    unsigned short dport;
    struct NatNode *next;
};

struct LogNode
{
    int year;
    int month;
    int day;
    int hour;
    int minute;
    int second;

    unsigned int sip;
    unsigned int dip;
    unsigned short sport;
    unsigned short dport;
    unsigned short protocol;

    unsigned int rule_sip;
    unsigned int rule_dip;
    unsigned short rule_sport;
    unsigned short rule_dport;
    unsigned short rule_protocol;
    bool rule_permit;

    struct LogNode *next;
};

namespace Ui
{
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

    void initCopyRight();

    void initFirewallTable();
    void addFirewallRuleToTable(Node item, unsigned int i);
    void refreshDefaultRuleFile();

    void initLinkTable();
    void addLinkRuleToTable(LinkNode item, unsigned int i);

    void initNatTable();
    void addNatRuleToTable(NatNode item, unsigned int i);

    void closeEvent(QCloseEvent *event);

    void warningBox(QString str);
    bool questionBox(QString title, QString msg, QString yesStr, QString noStr);

    bool checkIP(QString ipstr);
    bool checkPort(QString portStr);

    unsigned int inet_addr(char *str);
    QString getStringIPAddr(unsigned int ip);

    unsigned short getProtocolNumber(QString protocol);
    QString getProtocolName(unsigned short protocolNumber);

    unsigned short getPort(QString portStr);
    QString getPortName(unsigned int portNum);

    unsigned short getSubNetMaskNumber(QString ipstr);

private slots:
    void on_add_firewall_rule_Btn_clicked();
    void on_delete_firewall_rule_Btn_clicked();
    void on_clear_firewall_rule_Btn_clicked();
    void on_change_default_action_Btn_clicked();
    void on_rewrite_default_firewall_rule_Btn_clicked();

    void refreshLinkTable();

    void updateLogFile();

    void on_nat_start_Btn_clicked();
    void on_nat_stop_Btn_clicked();
    void refreshNatTable();

private:
    Ui::MainWindow *ui;

    int fd;

    // rules name
    QString rulesFilename;
    QVector<Node> ruleList;
    QLabel *statusLabel;
    unsigned int hostIP, hostIP_out;
    unsigned int hostnetmask;

    QTimer *link_timer;
    QTimer *log_timer;
    QTimer *nat_timer;
};

int getLocalIP(char *ifname, char *ip, char *netmask);
#endif // MAINWINDOW_H
