package queue

import "container/list"

type Queue[T any] struct {
	arr *list.List
}

func New[T any]() *Queue[T] {
	return &Queue[T]{
		arr: list.New(),
	}
}

func (q *Queue[T]) Enqueue(value T) {
	q.arr.PushBack(value)
}

func (q *Queue[T]) Dequeue() (t T, ok bool) {
	f := q.arr.Front()
	if f == nil {
		return
	}
	q.arr.Remove(f)
	return f.Value.(T), true
}
