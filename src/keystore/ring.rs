use std::mem;

pub struct FixedSizeRing<Item, const SIZE: usize> {
    items: [Option<Item>; SIZE],
    prev_head: usize,
    head: usize,
}

impl<Item, const SIZE: usize> FixedSizeRing<Item, SIZE> {
    /// Initializes a new empty instance of `FixedSizeRing`
    pub fn new() -> Self {
        assert!(SIZE > 0);
        Self {
            items: std::array::from_fn(|_| None),
            head: 0,
            prev_head: 0,
        }
    }

    /// Returns the latest pushed value
    pub fn last_pushed(&self) -> Option<&Item> {
        self.items
            .get(self.prev_head)
            .map(Option::as_ref)
            .unwrap_or(None)
    }

    /// Inserts a new item into the buffer and returns replaced item as a result if there's any
    pub fn push(&mut self, item: Item) -> Option<Item> {
        let next_head = (self.head + 1) % SIZE;
        self.prev_head = mem::replace(&mut self.head, next_head);
        mem::replace(&mut self.items[self.prev_head], Some(item))
    }

    /// Returns count of items in the collection
    pub fn count(&self) -> usize {
        self.items.iter().filter(|x| x.is_some()).count()
    }

    /// Returns an iterator over the items
    pub fn iter(&self) -> impl Iterator<Item = &Item> {
        self.items.iter().flatten()
    }
}

impl<Item, const SIZE: usize> Default for FixedSizeRing<Item, SIZE> {
    fn default() -> Self {
        Self::new()
    }
}
