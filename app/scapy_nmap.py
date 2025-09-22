from app.scanner import Scanner


class ScapyNmap(Scanner):
    def __init__(self, args):
        super().__init__(args)
