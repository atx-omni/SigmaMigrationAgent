"""Sigma-only registry; never discover unrelated installed source plugins."""


def get_extractor(name: str):
    if name != "sigma":
        raise KeyError("This distribution supports Sigma only")
    from omni_migrator.extractors.sigma.extractor import SigmaExtractor
    return SigmaExtractor()
