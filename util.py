def truncate(chars, num=10):
    return f'{chars[:num]}{"..." if len(chars) > num else ""}'