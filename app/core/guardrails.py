from typing import Dict, List, Tuple
from collections import deque

class AhoCorasick:
    """
    This is our high-speed engine for finding multiple things at once.
    Instead of searching for each word separately, we build a branch 
    for every letter and walk through them all together.
    """
    def __init__(self, patterns: List[str]):
        # The root of our search tree
        self.trie = [{'next': {}, 'fail': 0, 'output': []}]
        for pattern in patterns:
            self._insert(pattern)
        self._build_fail_links()

    def _insert(self, pattern: str):
        node = 0
        # We break down the secret into individual letters (nodes)
        for char in pattern:
            if char not in self.trie[node]['next']:
                # If this letter isn't in our path yet, we add a new branch
                self.trie[node]['next'][char] = len(self.trie)
                self.trie.append({'next': {}, 'fail': 0, 'output': []})
            node = self.trie[node]['next'][char]
        # At the end of the path, we mark that we've found a full match
        self.trie[node]['output'].append(pattern)

    def _build_fail_links(self):
        """
        These links are the 'Smart Shortcuts'. 
        If we fail to find the next letter in one word, we jump to 
        the next best possibility instead of starting over.
        """
        queue = deque()
        for char, child in self.trie[0]['next'].items():
            queue.append(child)
        
        while queue:
            u = queue.popleft()
            for char, v in self.trie[u]['next'].items():
                fail = self.trie[u]['fail']
                # Finding the next best node that matches our current suffix
                while char not in self.trie[fail]['next'] and fail != 0:
                    fail = self.trie[fail]['fail']
                self.trie[v]['fail'] = self.trie[fail]['next'].get(char, 0)
                # Keep track of any patterns that overlap here
                self.trie[v]['output'] += self.trie[self.trie[v]['fail']]['output']
                queue.append(v)

    def search_and_replace(self, text: str, replacement_map: Dict[str, str]) -> Tuple[str, int, set]:
        """
        This is the main scan. It walks through the text character by character 
        to find every pattern we're looking for in one single pass.
        Returns the new text, total matches, and a set of everything it found.
        """
        node = 0
        matches = [] # We'll store (start, end, pattern) to deal with overlaps later
        for i, char in enumerate(text):
            while char not in self.trie[node]['next'] and node != 0:
                node = self.trie[node]['fail']
            node = self.trie[node]['next'].get(char, 0)
            for pattern in self.trie[node]['output']:
                matches.append((i - len(pattern) + 1, i + 1, pattern))
        
        # We sort by the start position to make the replacement easier from left to right
        matches.sort()
        
        result = []
        last_idx = 0
        match_count = 0
        found_patterns = set()

        for start, end, pattern in matches:
            # Important: We only replace if the current match doesn't overlap with the last one
            if start >= last_idx:
                found_patterns.add(pattern)
                result.append(text[last_idx:start])
                result.append(replacement_map.get(pattern, pattern))
                last_idx = end
                match_count += 1
        
        # Append the remaining part of the text
        result.append(text[last_idx:])
        return "".join(result), match_count, found_patterns
