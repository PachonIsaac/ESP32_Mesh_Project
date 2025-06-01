#include <Arduino.h> // Necesario para PlatformIO con framework Arduino
#include <WiFi.h>
#include <esp_now.h>
#include <vector>
#include <string> // Para manejar cadenas de texto
#include <esp_wifi.h>

// =======================================================================
// ESTRUCTURAS Y DEFINICIONES GLOBALES
// =======================================================================

// Estructura para la información de un nodo conocido
typedef struct {
  uint8_t mac_addr[6];
} node_info_t;

// Estructura para el mensaje general
typedef struct {
  uint8_t type;
  uint8_t sender_mac[6];
  // Campos adicionales según el tipo de mensaje
  uint8_t payload[250]; // Tamaño máximo del payload (ajustar si es necesario)
} message_t;

// Estructura para el mensaje JOIN_REQUEST
typedef struct {
  uint8_t type;
  uint8_t sender_mac[6];
} join_request_message_t;

// Estructura para el mensaje BROADCAST
typedef struct {
  uint8_t type;
  uint8_t sender_mac[6];
  uint32_t message_id; // Identificador único del mensaje
  uint8_t ttl;         // Time To Live
  uint8_t payload[250]; // Contenido del mensaje
} broadcast_message_t;

// Estructura para el mensaje SEND (Unicast con enrutamiento)
typedef struct {
  uint8_t type;
  uint8_t sender_mac[6];
  uint8_t destination_mac[6];
  uint8_t hop_count; // Contador de saltos
  uint8_t max_hops;  // Límite máximo de saltos
  uint32_t message_id; // Para evitar duplicados en el reenvío
  uint8_t payload[250]; // Contenido del mensaje
} send_message_t;


// Tipos de mensajes
#define JOIN_REQUEST_TYPE   1
#define JOIN_RESPONSE_TYPE  2 // Para confirmar la unión
#define BROADCAST_TYPE      3
#define SEND_TYPE           4
#define LEAVE_TYPE          5
#define WIFI_CHANNEL 1

// =======================================================================
// VARIABLES GLOBALES
// =======================================================================
std::vector<node_info_t> known_nodes;
uint32_t broadcast_id_counter = 0; // Para generar IDs únicos para broadcast

// Para el control de mensajes duplicados de broadcast (almacena sender_mac + message_id)
// Podríamos usar un vector de pares o una estructura para esto
std::vector<std::pair<std::string, uint32_t>> processed_broadcast_messages;
const int MAX_PROCESSED_BROADCAST_MESSAGES = 20; // Limitar el tamaño para no agotar la memoria

// =======================================================================
// FUNCIONES AUXILIARES (prototipos)
// =======================================================================
void printMacAddress(const uint8_t *mac);
void printKnownNodes();
void add_node_to_known_list(const uint8_t *mac);
bool isMacInKnownNodes(const uint8_t *mac);
void remove_node_from_known_list(const uint8_t *mac);

// =======================================================================
// CALLBACKS DE ESP-NOW
// =======================================================================

// Callback para cuando se envía un mensaje
void OnDataSent(const uint8_t *mac_addr, esp_now_send_status_t status) {
  Serial.print("Estado de envío a ");
  printMacAddress(mac_addr);
  Serial.print(": ");
  if (status == ESP_NOW_SEND_SUCCESS) {
    Serial.println("Éxito");
  } else {
    Serial.println("Fallo");
  }
}

// Callback para cuando se recibe un mensaje
void OnDataRecv(const uint8_t *mac_addr, const uint8_t *data, int data_len) {
  Serial.print("Mensaje recibido de: ");
  printMacAddress(mac_addr);
  Serial.print(", longitud: ");
  Serial.println(data_len);

  // Asegúrate de que el mensaje tenga al menos el tamaño mínimo para el tipo
  if (data_len < sizeof(uint8_t)) {
    Serial.println("Mensaje recibido muy corto para determinar el tipo.");
    return;
  }

  uint8_t message_type = data[0]; // El primer byte es el tipo de mensaje

  switch (message_type) {
    case JOIN_REQUEST_TYPE: {
      if (data_len >= sizeof(join_request_message_t)) {
        join_request_message_t *join_req = (join_request_message_t *)data;
        Serial.print("Solicitud JOIN recibida de: ");
        printMacAddress(join_req->sender_mac);
        add_node_to_known_list(join_req->sender_mac);

        // Opcional: Enviar una respuesta JOIN_RESPONSE al nodo que se unió
        // Aquí podrías enviar tu propia MAC y la lista de nodos conocidos, por ejemplo
      } else {
        Serial.println("Mensaje JOIN_REQUEST incompleto.");
      }
      break;
    }
    case BROADCAST_TYPE: {
      if (data_len >= sizeof(broadcast_message_t)) {
        broadcast_message_t *b_msg = (broadcast_message_t *)data;
        Serial.print("Broadcast recibido de ");
        printMacAddress(b_msg->sender_mac);
        Serial.print(" ID: ");
        Serial.print(b_msg->message_id);
        Serial.print(", TTL: ");
        Serial.println(b_msg->ttl);
        Serial.print("Payload: ");
        // Imprimir payload de forma segura (asegurando que sea una cadena si lo esperas)
        for (int i = 0; i < data_len - offsetof(broadcast_message_t, payload); i++) {
            Serial.print((char)b_msg->payload[i]);
        }
        Serial.println();


        // Verificar si el mensaje ya fue procesado
        std::string sender_mac_str = "";
        for (int i = 0; i < 6; ++i) {
            char hex_byte[3];
            sprintf(hex_byte, "%02X", b_msg->sender_mac[i]);
            sender_mac_str += hex_byte;
        }
        bool already_processed = false;
        for (const auto& msg_id_pair : processed_broadcast_messages) {
            if (msg_id_pair.first == sender_mac_str && msg_id_pair.second == b_msg->message_id) {
                already_processed = true;
                break;
            }
        }

        if (already_processed) {
            Serial.println("Mensaje de broadcast duplicado, descartando.");
        } else {
            // Añadir a la lista de procesados
            processed_broadcast_messages.push_back({sender_mac_str, b_msg->message_id});
            if (processed_broadcast_messages.size() > MAX_PROCESSED_BROADCAST_MESSAGES) {
                processed_broadcast_messages.erase(processed_broadcast_messages.begin()); // Eliminar el más antiguo
            }

            // Si el TTL es mayor que 1, retransmitir
            if (b_msg->ttl > 1) {
                b_msg->ttl--; // Decrementar TTL
                // Retransmitir a todos los nodos conocidos, excepto al que lo envió originalmente
                for (const auto& node : known_nodes) {
                    if (memcmp(node.mac_addr, mac_addr, 6) != 0) { // No enviar de vuelta al remitente
                        esp_now_send(node.mac_addr, (uint8_t *)b_msg, sizeof(broadcast_message_t));
                        Serial.print("Retransmitiendo broadcast a ");
                        printMacAddress(node.mac_addr);
                    }
                }
            } else {
                Serial.println("TTL de broadcast agotado, no retransmitiendo.");
            }
        }
      } else {
        Serial.println("Mensaje BROADCAST incompleto.");
      }
      break;
    }
    case SEND_TYPE: {
        if (data_len >= sizeof(send_message_t)) {
            send_message_t *s_msg = (send_message_t *)data;
            uint8_t my_mac[6];
            WiFi.macAddress(my_mac);

            Serial.print("Mensaje SEND recibido de ");
            printMacAddress(s_msg->sender_mac);
            Serial.print(" para ");
            printMacAddress(s_msg->destination_mac);
            Serial.print(", saltos: ");
            Serial.println(s_msg->hop_count);
            Serial.print("Payload: ");
            for (int i = 0; i < data_len - offsetof(send_message_t, payload); i++) {
                Serial.print((char)s_msg->payload[i]);
            }
            Serial.println();

            // Si soy el destinatario
            if (memcmp(s_msg->destination_mac, my_mac, 6) == 0) {
                Serial.println("Soy el destinatario de este mensaje SEND.");
                // Aquí procesar el mensaje final
            } else {
                // No soy el destinatario, debo reenviar
                if (s_msg->hop_count < s_msg->max_hops) {
                    s_msg->hop_count++; // Incrementar contador de saltos

                    // Lógica de reenvío:
                    // Por ahora, simplemente reenvía al primer nodo conocido que no sea el remitente original
                    // Esto NO es un enrutamiento inteligente, es una inundación dirigida
                    bool forwarded = false;
                    for (const auto& node : known_nodes) {
                        if (memcmp(node.mac_addr, mac_addr, 6) != 0) { // No enviar de vuelta al remitente
                            // Asegurarse de que el destino es alcanzable desde este nodo o desde sus vecinos
                            // (Esto requeriría una tabla de enrutamiento más compleja)

                            // Por simplicidad en esta etapa, solo reenvía a un vecino si no es el remitente
                            // Una implementación robusta necesitaría buscar el mejor siguiente salto hacia destination_mac
                            esp_err_t result = esp_now_send(node.mac_addr, (uint8_t *)s_msg, sizeof(send_message_t));
                            if (result == ESP_OK) {
                                Serial.print("Reenviando SEND a ");
                                printMacAddress(node.mac_addr);
                                forwarded = true;
                                break; // Solo reenviar a un vecino por ahora, para evitar inundación excesiva
                            } else {
                                Serial.print("Error al reenviar SEND a ");
                                printMacAddress(node.mac_addr);
                                Serial.println(esp_err_to_name(result));
                            }
                        }
                    }
                    if (!forwarded) {
                        Serial.println("No se pudo reenviar el mensaje SEND (no hay vecino adecuado).");
                    }
                } else {
                    Serial.println("Mensaje SEND descartado: máximo de saltos alcanzado.");
                }
            }
        } else {
            Serial.println("Mensaje SEND incompleto.");
        }
        break;
    }
    case LEAVE_TYPE: {
        if (data_len >= sizeof(message_t)) { // Solo necesitamos el tipo y sender_mac
            message_t *leave_msg = (message_t *)data;
            Serial.print("Solicitud LEAVE recibida de: ");
            printMacAddress(leave_msg->sender_mac);
            remove_node_from_known_list(leave_msg->sender_mac);
            // Aquí podrías implementar la difusión de la información de LEAVE a otros nodos
        } else {
            Serial.println("Mensaje LEAVE incompleto.");
        }
        break;
    }
    default:
      Serial.print("Tipo de mensaje desconocido: ");
      Serial.println(message_type);
      break;
  }
}

// =======================================================================
// FUNCIONES DE COMANDO
// =======================================================================

// Función para enviar un mensaje de broadcast
void send_broadcast_message(const std::string& msg_payload) {
  broadcast_message_t b_msg;
  b_msg.type = BROADCAST_TYPE;
  WiFi.macAddress(b_msg.sender_mac);
  b_msg.message_id = broadcast_id_counter++; // Incrementa para cada nuevo broadcast
  b_msg.ttl = 5; // TTL inicial (ajustar según el tamaño de la red)

  // Copiar el payload, asegurando que no exceda el tamaño máximo
  strncpy((char*)b_msg.payload, msg_payload.c_str(), sizeof(b_msg.payload) - 1);
  b_msg.payload[sizeof(b_msg.payload) - 1] = '\0'; // Asegurar terminación nula

  // Iterar sobre los nodos conocidos para enviar el mensaje (primera fase de inundación)
  if (known_nodes.empty()) {
    Serial.println("No hay nodos conocidos para enviar el broadcast.");
    return;
  }

  // Asegurarse de que todos los nodos conocidos estén agregados como peers de ESP-NOW
  for (const auto& node : known_nodes) {
    if (!esp_now_is_peer_exist(node.mac_addr)) {
      esp_now_peer_info_t peerInfo;
      memset(&peerInfo, 0, sizeof(peerInfo));
      memcpy(peerInfo.peer_addr, node.mac_addr, 6);
      peerInfo.channel = 0; // Usar el canal actual
      peerInfo.encrypt = false;
      if (esp_now_add_peer(&peerInfo) != ESP_OK) {
        Serial.print("Error al añadir peer ");
        printMacAddress(node.mac_addr);
      }
    }
  }

  for (const auto& node : known_nodes) {
    esp_err_t result = esp_now_send(node.mac_addr, (uint8_t *)&b_msg, sizeof(broadcast_message_t));
    if (result != ESP_OK) {
      Serial.print("Error al enviar broadcast a ");
      printMacAddress(node.mac_addr);
      Serial.println(esp_err_to_name(result));
    }
  }
  Serial.println("Mensaje de broadcast enviado a los vecinos conocidos.");
}

// Función para enviar un mensaje unicast (send)
void send_unicast_message(const uint8_t *dest_mac, const std::string& msg_payload) {
  send_message_t s_msg;
  s_msg.type = SEND_TYPE;
  WiFi.macAddress(s_msg.sender_mac);
  memcpy(s_msg.destination_mac, dest_mac, 6);
  s_msg.hop_count = 0;
  s_msg.max_hops = 5; // Máximo de saltos para evitar bucles infinitos
  s_msg.message_id = esp_random(); // ID único para el mensaje unicast

  strncpy((char*)s_msg.payload, msg_payload.c_str(), sizeof(s_msg.payload) - 1);
  s_msg.payload[sizeof(s_msg.payload) - 1] = '\0'; // Asegurar terminación nula

  // Intentar enviar directamente al destinatario si es un nodo conocido
  // Esto es una simplificación; un enrutamiento real implica buscar el mejor "siguiente salto"
  if (isMacInKnownNodes(dest_mac)) {
      esp_now_peer_info_t peerInfo;
      memset(&peerInfo, 0, sizeof(peerInfo));
      memcpy(peerInfo.peer_addr, dest_mac, 6);
      peerInfo.channel = 0;
      peerInfo.encrypt = false;

      // Asegurar que el destino esté agregado como peer
      if (!esp_now_is_peer_exist(dest_mac)) {
        if (esp_now_add_peer(&peerInfo) != ESP_OK) {
          Serial.print("Error al agregar peer para SEND ");
          printMacAddress(dest_mac);
          Serial.println();
          return;
        }
      }

      esp_err_t result = esp_now_send(dest_mac, (uint8_t *)&s_msg, sizeof(send_message_t));
      if (result == ESP_OK) {
        Serial.print("Mensaje SEND enviado directamente a ");
        printMacAddress(dest_mac);
      } else {
        Serial.print("Error al enviar directamente SEND a ");
        printMacAddress(dest_mac);
        Serial.println(esp_err_to_name(result));
      }
  } else {
      Serial.print("El nodo ");
      printMacAddress(dest_mac);
      Serial.println(" no es un vecino conocido. Iniciando reenvío.");
      // Aquí se activaría la lógica de enrutamiento más compleja:
      // Podrías enviar a todos los vecinos y que ellos reenvíen hasta que el mensaje llegue al destino
      // (similar a un broadcast, pero con una MAC de destino y control de saltos).
      // Por ahora, para la "profundidad", si no es un vecino directo, lo reenviamos a todos los conocidos.
      for (const auto& node : known_nodes) {
          esp_err_t result = esp_now_send(node.mac_addr, (uint8_t *)&s_msg, sizeof(send_message_t));
          if (result != ESP_OK) {
              Serial.print("Error al iniciar reenvío SEND a ");
              printMacAddress(node.mac_addr);
              Serial.println(esp_err_to_name(result));
          }
      }
      Serial.println("Mensaje SEND reenviado a vecinos para alcanzar el destino.");
  }
}

// Función para unirse a la red
void join_network(const uint8_t *known_node_mac_addr) {
  join_request_message_t join_msg;
  join_msg.type = JOIN_REQUEST_TYPE;
  WiFi.macAddress(join_msg.sender_mac);

  esp_now_peer_info_t peerInfo;
  memset(&peerInfo, 0, sizeof(peerInfo));
  memcpy(peerInfo.peer_addr, known_node_mac_addr, 6);
  uint8_t primary_channel;
  wifi_second_chan_t second;
  esp_wifi_get_channel(&primary_channel, &second);
  peerInfo.channel = primary_channel;
  peerInfo.encrypt = false;

  if (esp_now_is_peer_exist(known_node_mac_addr) == false) {
    esp_err_t add_status = esp_now_add_peer(&peerInfo);
    if (add_status != ESP_OK) {
      Serial.print("Error al agregar peer para JOIN: ");
      Serial.println(esp_err_to_name(add_status));
      return;
    }
  }

  esp_err_t send_status = esp_now_send(known_node_mac_addr, (uint8_t *)&join_msg, sizeof(join_request_message_t));
  if (send_status == ESP_OK) {
    Serial.println("Solicitud JOIN enviada correctamente");
    // Agrega el nodo destino a la lista de conocidos
    add_node_to_known_list(known_node_mac_addr);
  } else {
    Serial.print("Error al enviar la solicitud JOIN: ");
    Serial.println(esp_err_to_name(send_status));
  }
}

// Función para abandonar la red
void leave_network() {
    message_t leave_msg; // Reutilizamos message_t ya que solo necesitamos tipo y sender_mac
    leave_msg.type = LEAVE_TYPE;
    WiFi.macAddress(leave_msg.sender_mac);

    // Enviar el mensaje LEAVE a todos los nodos conocidos
    for (const auto& node : known_nodes) {
        esp_err_t result = esp_now_send(node.mac_addr, (uint8_t *)&leave_msg, sizeof(message_t));
        if (result != ESP_OK) {
            Serial.print("Error al enviar LEAVE a ");
            printMacAddress(node.mac_addr);
            Serial.println(esp_err_to_name(result));
        }
    }
    Serial.println("Mensaje LEAVE enviado a todos los nodos conocidos.");

    // Opcional: limpiar la lista de nodos conocidos localmente
    known_nodes.clear();
    Serial.println("Lista local de nodos conocidos borrada.");
}


// =======================================================================
// ENTRADA DE COMANDOS POR CONSOLA
// =======================================================================

void handle_serial_input() {
  if (Serial.available()) {
    std::string command = Serial.readStringUntil('\n').c_str();
    command.erase(command.find_last_not_of(" \n\r\t") + 1); // Eliminar espacios en blanco y saltos de línea

    Serial.print("Comando recibido: '");
    Serial.print(command.c_str());
    Serial.println("'");

    if (command.rfind("join ", 0) == 0) { // Si el comando empieza con "join "
      std::string mac_str = command.substr(5); // Obtener la MAC después de "join "
      uint8_t mac[6];
      unsigned int mac_bytes[6];
      if (sscanf(mac_str.c_str(), "%x:%x:%x:%x:%x:%x",
                 &mac_bytes[0], &mac_bytes[1], &mac_bytes[2],
                 &mac_bytes[3], &mac_bytes[4], &mac_bytes[5]) == 6) {
        for (int i = 0; i < 6; ++i) {
          mac[i] = (uint8_t)mac_bytes[i];
        }
        join_network(mac);
      } else {
        Serial.println("Formato de MAC incorrecto. Uso: join XX:XX:XX:XX:XX:XX");
      }
    } else if (command.rfind("broadcast ", 0) == 0) {
        std::string payload = command.substr(10); // Obtener el payload después de "broadcast "
        send_broadcast_message(payload); 
    } else if (command.rfind("send ", 0) == 0) {
        // Formato: send XX:XX:XX:XX:XX:XX mensaje
        size_t first_space = command.find(' ');
        size_t second_space = command.find(' ', first_space + 1);
        if (first_space != std::string::npos && second_space != std::string::npos) {
            std::string mac_str = command.substr(first_space + 1, second_space - (first_space + 1));
            std::string payload = command.substr(second_space + 1);

            uint8_t mac[6];
            unsigned int mac_bytes[6];
            if (sscanf(mac_str.c_str(), "%x:%x:%x:%x:%x:%x",
                       &mac_bytes[0], &mac_bytes[1], &mac_bytes[2],
                       &mac_bytes[3], &mac_bytes[4], &mac_bytes[5]) == 6) {
              for (int i = 0; i < 6; ++i) {
                mac[i] = (uint8_t)mac_bytes[i];
              }
              send_unicast_message(mac, payload);
            } else {
              Serial.println("Formato de MAC incorrecto para send. Uso: send XX:XX:XX:XX:XX:XX mensaje");
            }
        } else {
            Serial.println("Formato incorrecto. Uso: send XX:XX:XX:XX:XX:XX mensaje");
        }
    } else if (command == "leave") {
        leave_network();
    }
    else if (command == "status") {
      Serial.print("MAC: ");
      uint8_t my_mac[6];
      WiFi.macAddress(my_mac);
      printMacAddress(my_mac);
      printKnownNodes();
    }
    else {
      Serial.println("Comando desconocido. Comandos: join <MAC>, broadcast <mensaje>, send <MAC> <mensaje>, leave, status");
    }
  }
}

// =======================================================================
// FUNCIONES AUXILIARES (implementación)
// =======================================================================

void printMacAddress(const uint8_t *mac) {
  for (int i = 0; i < 6; i++) {
    if (mac[i] < 16) Serial.print("0");
    Serial.print(mac[i], HEX);
    if (i < 5) Serial.print(":");
  }
  Serial.println();
}

void printKnownNodes() {
  Serial.println("--- Nodos Conocidos ---");
  if (known_nodes.empty()) {
    Serial.println("Ningún nodo conocido aún.");
  } else {
    for (const auto& node : known_nodes) {
      printMacAddress(node.mac_addr);
    }
  }
  Serial.println("-----------------------");
}

void add_node_to_known_list(const uint8_t *mac) {
  if (!isMacInKnownNodes(mac)) {
    node_info_t new_node;
    memcpy(new_node.mac_addr, mac, 6);
    known_nodes.push_back(new_node);
    Serial.println("Nodo agregado a la lista de conocidos.");
    printKnownNodes();
    // Cuando agregamos un nuevo nodo, también lo agregamos como peer de ESP-NOW
    esp_now_peer_info_t peerInfo;
    memset(&peerInfo, 0, sizeof(peerInfo));
    memcpy(peerInfo.peer_addr, mac, 6);
    peerInfo.channel = 0;
    peerInfo.encrypt = false;
    if (esp_now_add_peer(&peerInfo) != ESP_OK) {
      Serial.print("Error al añadir peer ESP-NOW para ");
      printMacAddress(mac);
    } else {
      Serial.print("Peer ESP-NOW añadido para ");
      printMacAddress(mac);
    }
  } else {
    Serial.println("Nodo ya estaba en la lista de conocidos.");
  }
}

bool isMacInKnownNodes(const uint8_t *mac) {
  for (const auto& node : known_nodes) {
    if (memcmp(node.mac_addr, mac, 6) == 0) {
      return true;
    }
  }
  return false;
}

void remove_node_from_known_list(const uint8_t *mac) {
    for (auto it = known_nodes.begin(); it != known_nodes.end(); ++it) {
        if (memcmp(it->mac_addr, mac, 6) == 0) {
            known_nodes.erase(it);
            Serial.print("Nodo ");
            printMacAddress(mac);
            Serial.println(" eliminado de la lista de conocidos.");

            // También eliminarlo como peer de ESP-NOW
            esp_err_t del_status = esp_now_del_peer(mac);
            if (del_status != ESP_OK) {
                Serial.print("Error al eliminar peer ESP-NOW para ");
                printMacAddress(mac);
            } else {
                Serial.print("Peer ESP-NOW eliminado para ");
                printMacAddress(mac);
            }
            printKnownNodes();
            return;
        }
    }
    Serial.print("Nodo ");
    printMacAddress(mac);
    Serial.println(" no encontrado en la lista de conocidos para eliminar.");
}

// =======================================================================
// SETUP Y LOOP PRINCIPAL
// =======================================================================

void setup() {
  Serial.begin(115200);
  Serial.println("\nInicializando ESP-NOW Mesh Node...");

  // Establecer el modo Wi-Fi en estación
  WiFi.mode(WIFI_STA);
  Serial.print("Modo Wi-Fi: ");
  if (WiFi.getMode() == WIFI_STA) {
    Serial.println("Estacion (WIFI_STA)");
  } else {
    Serial.println("Otro modo Wi-Fi. Esto podria ser un problema.");
  }

  Serial.print("Mi direccion MAC: ");
  Serial.println(WiFi.macAddress());

  // Inicializar ESP-NOW
  if (esp_now_init() != ESP_OK) {
    Serial.println("Error al inicializar ESP-NOW. Reiniciando...");
    ESP.restart(); // Reiniciar si falla la inicialización
    return;
  }
  Serial.println("ESP-NOW inicializado correctamente.");

  // Registrar las funciones de callback de ESP-NOW
  esp_now_register_send_cb(OnDataSent);
  esp_now_register_recv_cb(OnDataRecv);

  Serial.println("Listo para comandos. Escribe 'help' para ver los comandos disponibles.");
  Serial.println("Comandos disponibles:");
  Serial.println("  join <MAC_DEL_NODO_CONOCIDO> (e.g., join 78:21:84:81:0C:04)");
  Serial.println("  broadcast <mensaje>");
  Serial.println("  send <MAC_DESTINO> <mensaje>");
  Serial.println("  leave");
  Serial.println("  status");
}

void loop() {
  handle_serial_input();
  // Aquí puedes agregar otras tareas no relacionadas con la comunicación, si las tienes.
  delay(10); // Pequeña espera para no saturar el CPU
}