package go_mtr

func Error(errCh chan error, err error) {
	select {
	case errCh <- err:
	default:
	}
}
