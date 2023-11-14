/* pins 6, 7, 8 - NC */

#define pin_sw_brown 2
#define pin_sw_green 3

#define pin_led1_amber 13
#define pin_led2_red 12
#define pin_led3_green 11
#define pin_led4_amber 10
#define pin_led5_red 9

#define pin_relay_socket 4
#define pin_usb_sw 5

#define st_ack 0
#define st_error 1

#define st_mount_min B0010
#define st_mount_idle B0100
#define st_mount_busy B0110
#define st_mount_mounted B1000
#define st_mount_max B1000

#define st_relay_min B1010
#define st_relay_on B1010
#define st_relay_off B1100
#define st_relay_max B1100

#define st_usb_enable B1110

#define st_status B0010000
#define st_unmount B0100000

#define loop_delay_ms 500
#define usb_sw_timeout_ms 240000 // 4min


byte led_state = 0;

void led_state_apply() {
	digitalWrite(pin_led1_amber, led_state & B00001);
	digitalWrite(pin_led2_red, led_state & B00010);
	digitalWrite(pin_led3_green, led_state & B00100);
	digitalWrite(pin_led4_amber, led_state & B01000);
	digitalWrite(pin_led5_red, led_state & B10000); // used for relay status
}


int mount_state = st_mount_idle;
int relay_flip = 0, relay_state = 0;
unsigned long relay_flip_ts = 0;

int usb_enable = 0, usb_sw_state = 0;
unsigned long usb_enable_ts = 0;

void send_cmd(byte st) {
	if (Serial.availableForWrite() < 1) return;
	Serial.write(st);
	Serial.flush();
}

void handle_cmd(byte st) {
	if (st >= st_mount_min && st <= st_mount_max) mount_state = st;
	else if (st >= st_relay_min && st <= st_relay_max) {
		int relay_chk = st == st_relay_on;
		if (relay_chk != relay_state) relay_flip = 1; }
	else if (st == st_usb_enable) usb_enable = 1;
	else return send_cmd(st_error);
	send_cmd(st_ack);
}

void handle_button_umount() {
	if (!(digitalRead(pin_sw_green) ^ 1)) return;
	send_cmd(st_unmount);
	led_state = (led_state & B11111) | B01111;
	led_state_apply();
}

void handle_button_relay() {
	if (!(digitalRead(pin_sw_brown) ^ 1) || relay_flip) return;
	unsigned long ts = millis();
	if (ts - relay_flip_ts < loop_delay_ms) return; // debounce
	relay_flip = 1;
	relay_flip_ts = ts;
}


void setup() {
	pinMode(pin_led1_amber, OUTPUT);
	digitalWrite(pin_led1_amber, 0);
	pinMode(pin_led2_red, OUTPUT);
	digitalWrite(pin_led2_red, 0);
	pinMode(pin_led3_green, OUTPUT);
	digitalWrite(pin_led3_green, 0);
	pinMode(pin_led4_amber, OUTPUT);
	digitalWrite(pin_led4_amber, 0);
	pinMode(pin_led5_red, OUTPUT);
	digitalWrite(pin_led5_red, 0);

	pinMode(pin_relay_socket, OUTPUT);
	digitalWrite(pin_relay_socket, 0);

	pinMode(pin_sw_green, INPUT_PULLUP);
	attachInterrupt(
		digitalPinToInterrupt(pin_sw_green),
		handle_button_umount, CHANGE );

	pinMode(pin_sw_brown, INPUT_PULLUP);
	attachInterrupt(
		digitalPinToInterrupt(pin_sw_brown),
		handle_button_relay, CHANGE );

	pinMode(pin_usb_sw, OUTPUT);
	digitalWrite(pin_usb_sw, 0);

	Serial.begin(115200);
	Serial.setTimeout(500); // for write() only
	send_cmd(st_status);
}

void serialEvent() {
	while (Serial.available()) {
		int c = Serial.read();
		if (c == -1) return; // should not happen
		handle_cmd((byte) c); }
}


void loop() {
	delay(loop_delay_ms);
	byte led_state_last = led_state;

	byte led_state_mount = led_state & B01111;
	switch (mount_state) {
		case st_mount_busy:
			led_state_mount = led_state_mount ? 0 : B01111;
			break;
		case st_mount_mounted:
			led_state_mount = (led_state_mount << 1) & B01111;
			if (led_state_mount == 0) led_state_mount = 1;
			break;
		default: led_state_mount = 0; break; }

	if (relay_flip) {
		relay_flip = 0;
		relay_state = relay_state ^ 1;
		digitalWrite(pin_relay_socket, relay_state); }

	if (usb_enable) {
		usb_enable = 0;
		usb_enable_ts = millis();
		if (!usb_sw_state) digitalWrite(pin_usb_sw, usb_sw_state = 1);
	} else if (usb_sw_state) {
		unsigned long ts = millis();
		if (ts < usb_enable_ts) usb_enable_ts = 0; // millis overflow
		ts -= usb_enable_ts;
		if (ts > usb_sw_timeout_ms) digitalWrite(pin_usb_sw, usb_sw_state = 0); }

	led_state = (led_state_mount & B01111) | ((relay_state & 1) << 4);
	if (led_state != led_state_last) led_state_apply();
}
