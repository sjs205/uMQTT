
#include "uMQTT_msg_resp.h"

int main() {
  struct broker_conn *conn;

  init_connection(&conn);
  if (!conn)
    return -1;

  broker_connect(conn);
  do {
  }while (1);
}

