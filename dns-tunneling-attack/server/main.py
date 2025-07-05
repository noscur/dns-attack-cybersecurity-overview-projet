from threading import Thread
from objects.QueriesManager import QueriesManager
from objects.AdminInterface import AdminInterface

host = "0.0.0.0"
port = 53

admin_interface_host = "0.0.0.0"
admin_interface_port = 3000

try:
    queries_manager = QueriesManager()
    mainthread = Thread(target=queries_manager.start, args=(host, port))
    mainthread.start()
    admin_interface = AdminInterface(
        admin_interface_host, admin_interface_port, queries_manager
    )
    admin_interface_thread = Thread(target=admin_interface.start, args=(host, port))
    admin_interface_thread.start()
    admin_interface_thread.join()
except KeyboardInterrupt:
    print("Server stoped.")

finally:
    queries_manager.close()
    admin_interface.close()
