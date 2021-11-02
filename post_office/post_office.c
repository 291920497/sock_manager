#include "sorting_center.h"
#include "front_desk.h"
#include "messenger/messenger.h"




/******************************************************* 分拣中心 *******************************************************/

sorting_center_t* sc_start_business() {
	int32_t rt = 0;
	sorting_center_t* sc = malloc(sizeof(sorting_center_t));
	if (sc) {
		memset(sc, 0, sizeof(sorting_center_t));
		sc->bells[0] = -1;
		sc->bells[1] = -1;
		CDS_INIT_LIST_HEAD(&sc->list_complate_inbox);
		CDS_INIT_LIST_HEAD(&sc->list_complate_outbox);

//		CDS_INIT_LIST_HEAD(&sc->list_pending_inbox);

		sc->ht = ht_create_heap_timer();
		if (!sc->ht)
			goto start_business_failed;


		if (socketpair(AF_UNIX, SOCK_STREAM, 0, &sc->bells) == -1)
			goto start_business_failed;

		if (pthread_spin_init(&sc->lock_inbox, PTHREAD_PROCESS_PRIVATE))
			rt |= 1;
		if (pthread_spin_init(&sc->lock_outbox, PTHREAD_PROCESS_PRIVATE))
			rt |= 2;

		//虽然从未发生过, 但是万一呢
		if (rt)
			goto start_business_failed;

		return sc;
	}

start_business_failed:
	if (sc->ht)
		ht_destroy_heap_timer(sc->ht);

	if (sc->bells[0] != 0) {
		close(sc->bells[0]);
		sc->bells[0] = -1;

		close(sc->bells[1]);
		sc->bells[1] = -1;
	}

	if (rt) {
		if (rt & 1)
			pthread_spin_destroy(&sc->lock_inbox);
		if (rt & 2)
			pthread_spin_destroy(&sc->lock_outbox);
	}

	free(sc);
	return 0;
}

void sc_outof_business(sorting_center_t* sc) {
	if (sc) {
		messenger_t* pos, * n;
		pthread_spin_lock(&sc->lock_inbox);

		cds_list_for_each_entry_safe(pos, n, &sc->list_complate_inbox, elem_fifo) {
			printf("2\n");
			msger_fire(pos);
			
		}

		pthread_spin_unlock(&sc->lock_inbox);


		pthread_spin_lock(&sc->lock_outbox);

		cds_list_for_each_entry_safe(pos, n, &sc->list_complate_outbox, elem_fifo) {
			printf("3\n");
			msger_fire(pos);
		
		}

		pthread_spin_unlock(&sc->lock_outbox);


		pthread_spin_destroy(&sc->lock_inbox);
		pthread_spin_destroy(&sc->lock_outbox);

		ht_destroy_heap_timer(sc->ht);

		close(sc->bells[0]);
		close(sc->bells[1]);
		free(sc);
	}
}

void sc_merge_box2complate_inbox(sorting_center_t* sc, cds_list_head_t* box) {
	if (!cds_list_empty(box)) {
		pthread_spin_lock(&sc->lock_inbox);
		cds_list_splice_tail(box, &sc->list_complate_inbox);
		pthread_spin_unlock(&sc->lock_inbox);
		CDS_INIT_LIST_HEAD(box);
	}
}

void sc_solicitation_inthe_inbox(sorting_center_t* sc, cds_list_head_t* box) {
	pthread_spin_lock(&sc->lock_inbox);
	if (cds_list_empty(&sc->list_complate_inbox) == 0) {
		cds_list_splice_tail(&sc->list_complate_inbox, box);
		CDS_INIT_LIST_HEAD(&sc->list_complate_inbox);
	}
	pthread_spin_unlock(&sc->lock_inbox);
}

void sc_submit_to_outbox(sorting_center_t* sc, cds_list_head_t* box) {
	if (!cds_list_empty(box)) {
		pthread_spin_lock(&sc->lock_outbox);
		cds_list_splice_tail(box, &sc->list_complate_outbox);
		pthread_spin_unlock(&sc->lock_outbox);
		CDS_INIT_LIST_HEAD(box);
	}
}

//从发件箱中揽件到box
void sc_solicitation_inthe_outbox(sorting_center_t* sc, cds_list_head_t* box) {
	pthread_spin_lock(&sc->lock_outbox);
	if (!cds_list_empty(&sc->list_complate_outbox)) {
		cds_list_splice_tail(&sc->list_complate_outbox, box);
		CDS_INIT_LIST_HEAD(&sc->list_complate_outbox);
	}
	pthread_spin_unlock(&sc->lock_outbox);
}


void sc_bells1_took_the_letter(sorting_center_t* sc) {
	char ctl = SORT_CLEN_SORTING_INBOX;
	write(sc->bells[1], &ctl, sizeof(char));
}

//告知送来了信件
void sc_bells1_sent_a_letter(sorting_center_t* sc) {
	char ctl = SORT_NEED_SORTING_OUTBOX;
	write(sc->bells[1], &ctl, sizeof(char));
}

void sc_how2do_example(sorting_center_t* sc, cds_list_head_t* box) {
	messenger_t* pos, * n, * msger;
	letter_t* l, * r;
	letter_information_t* linfo;
	uint32_t len, tehme;

	//发件箱
	cds_list_head_t outbox;
	CDS_INIT_LIST_HEAD(&outbox);

	if (!cds_list_empty(box)) {
		cds_list_for_each_entry_safe(pos, n, box, elem_fifo) {
			//先断开联系
			cds_list_del_init(&pos->elem_fifo);

			linfo = pos->information;
			//请求信使的座位
			//msger_seat = 0;
			//招募一个信使, 原本是准备放入回调中去做的, 但是可能对使用者的成本太高了
			msger = msger_hire();
			if (!msger) {
				msger_fire(pos);
				continue;
			}
			
			//memcpy(msger->information, pos->information, sizeof(letter_information_t));

			if (!cds_list_empty(&pos->list_paragraphs)) {
				cds_list_for_each_entry_safe(l, r, &pos->list_paragraphs, elem_paragraph) {
					//如果这个session已经关闭读端, 那么不应该接收写的数据了
					tehme = l->theme | (l->theme & THEME_DESTORY ? THEME_DESTORY : 0);
					l->behav(linfo->hash, tehme, RWBUF_START_PTR(&l->sentence), RWBUF_GET_LEN(&l->sentence), pos->character_len, linfo->encode_fn, linfo->udata, linfo->udata_len, msger);
					if (RWBUF_GET_LEN(&l->sentence)) 
						pos->character_len -= RWBUF_GET_LEN(&l->sentence);
				}
			}

			//若信使收到了新的信件
			if (!cds_list_empty(&msger->list_paragraphs) && !linfo->closed) {
				memcpy(msger->information, pos->information, sizeof(letter_information_t));
				cds_list_add_tail(&msger->elem_fifo, &outbox);
			}else
				msger_fire(msger);

			//送信的信使任务完成
			msger_fire(pos);
		}
	}

	//让所有的信使排队放入收件箱
	if (!cds_list_empty(&outbox)) {
		sc_submit_to_outbox(sc, &outbox);
		sc_bells1_sent_a_letter(sc);
	}
		
}

void* sc_thread_assembly_line(void* p) {
	sorting_center_t* sc = (sorting_center_t*)p;

	sc->opening = 1;
	int fd = sc->bells[1];

	int rt, flag;
	uint64_t waitms;
	messenger_t* pos, * n;
	fd_set fdst;
	struct timeval tv;
	char buf[2048];

	cds_list_head_t letters;
	CDS_INIT_LIST_HEAD(&letters);


	while (sc->opening) {
		waitms = ht_update_timer(sc->ht);

		tv.tv_sec = waitms / 1000;
		tv.tv_usec = (waitms - tv.tv_sec * 1000) * 1000;

		FD_ZERO(&fdst);
		FD_SET(fd, &fdst);

		rt = select(fd + 1, &fdst, NULL, NULL, &tv);
		if (rt == -1) {
			if (errno != EINTR) { return -1; }

			//信号
			continue;
		}
		else if (rt == 0)
			continue;

		if (FD_ISSET(fd, &fdst)) {
			rt = recv(fd, buf, sizeof(buf), 0);
			if (rt == 0) {
				sc->opening = 0;
				continue;
			}
			else if (rt == -1 && errno != EAGAIN) {
				sc->opening = 0;
				continue;
			}

			for (int i = 0; i < rt; ++i) {
				if (buf[i] == SORT_NEED_SORTING_INBOX) {
					sc_solicitation_inthe_inbox(sc, &letters);

					//通知主线程, 消息已经被拿走
					char ctl = SORT_CLEN_SORTING_INBOX;
					write(fd, &ctl, sizeof(char));
				}
			}

			sc_how2do_example(sc, &letters);
		}
	}

}


/******************************************************* 分拣中心 *******************************************************/


/********************************************************* 前台 *********************************************************/

//招募一个信使
messenger_t* frontd_hire_messenger(uint32_t hash, void* session_address) {
	messenger_t* msger = msger_hire();
	if (!msger)
		return NULL;

	memset(msger, 0, sizeof(messenger_t));
	msger->information->hash = hash;
	msger->information->address = session_address;

	return msger;
}

void frontd_fire_messenger(messenger_t* msger) {
	msger_fire(msger);
}

void front_detach_messenger(sorting_center_t* sc, messenger_t* msger) {
	if (!cds_list_empty(&msger->list_paragraphs))
		msger_fire(msger);
	else {
		pthread_spin_lock(&sc->lock_outbox);
		cds_list_add_tail(&msger->elem_fifo, &sc->list_complate_outbox);
		pthread_spin_unlock(&sc->lock_outbox);
	}
}

/********************************************************* 前台 *********************************************************/