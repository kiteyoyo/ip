# ip

登入mysql:
mysql -u root -p

因為使用中文，所以再最初創建Database時就要使用utf-8，在此設定的database名為manage
CREATE DATABASE <dbname> CHARACTER SET utf8;
info from: https://docs.djangoproject.com/en/1.9/ref/databases/

在setting裡可以給予基本設定
如果有database可以完全取得的話就使用database裡的, 否則就會使用local的設定, 但top_switch_ip都是看local的

top_switch_ip:
最頂端的switch

get_port_timeout=[5, 60, 10]:
[經過多少輪沒在switch找到指定mac就啟動rescue ability, 經過多少輪沒在switch找到指定mac就發出'get ip timeout'Exception, 經過幾秒之後從新取得switch資料]

switch_list:
請輸入switch的相關訊息,type有cisco和juniper兩種可以選擇,user為使用者帳號,password為此使用者的密碼

line_list:
請輸入由頂端switch往下,互相有串連的switch,較接近頂端的為start,反之為end,分別要輸入ip和port

detail_list:
可以直接紀錄哪個switch下的哪個port的確定資訊,會在之後顯示的多一格detail,補充說明相關資訊

server/setting/example.json提供舉例
