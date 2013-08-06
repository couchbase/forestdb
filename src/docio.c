/*
 * Copyright 2013 Jung-Sang Ahn <jungsang.ahn@gmail.com>.
 * All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "docio.h"

void docio_init(struct docio_handle *handle, struct filemgr *file)
{
    handle->file = file;
    handle->curblock = BLK_NOT_FOUND;
    handle->curpos = 0;
}

INLINE bid_t docio_append_doc_raw(struct docio_handle *handle, uint64_t size, void *buf)
{
	bid_t bid;
	uint32_t offset;
	
	if (handle->curblock == BLK_NOT_FOUND) {
		// allocate new block
		handle->curblock = filemgr_alloc(handle->file);
		handle->curpos = 0;
	}
	if (!filemgr_is_writable(handle->file, handle->curblock)) {
		// allocate new block
		handle->curblock = filemgr_alloc(handle->file);
		handle->curpos = 0;
	}

#ifdef DOCIO_BLOCK_ALIGN
	// block aligning mode
	if (size <= handle->file->blocksize - handle->curpos) {
		// simply append to current block
		offset = handle->curpos;
		filemgr_write_offset(handle->file, handle->curblock, offset, size, buf);

		handle->curpos += size;

		return handle->curblock * handle->file->blocksize + offset;
		
	}else{
		// not simply fitted into current block
		bid_t begin, end, i, startpos;
		uint32_t nblock = size / handle->file->blocksize;
		uint32_t remain = size % handle->file->blocksize;
		uint64_t remainsize = size;

		if (remain <= handle->file->blocksize - handle->curpos && 
			filemgr_get_next_alloc_block(handle->file) == handle->curblock+1) {
			// start from current block
			filemgr_alloc_multiple(handle->file, nblock, &begin, &end);
			assert(begin == handle->curblock + 1);
			
			offset = handle->file->blocksize - handle->curpos;
			filemgr_write_offset(handle->file, handle->curblock, handle->curpos, offset, buf);
			remainsize -= offset;

			startpos = handle->curblock * handle->file->blocksize + handle->curpos;			
		}else {
			// allocate new multiple blocks
			filemgr_alloc_multiple(handle->file, nblock+1, &begin, &end);
			offset = 0;

			startpos = begin * handle->file->blocksize;
		}

		for (i=begin; i<=end; ++i) {
			handle->curblock = i;
			if (remainsize >= handle->file->blocksize) {
				// write entire block
				filemgr_write(handle->file, i, buf + offset);
				offset += handle->file->blocksize;
				remainsize -= handle->file->blocksize;
				handle->curpos = handle->file->blocksize;
				
			}else{
				// write rest of document
				assert(i==end);
				filemgr_write_offset(handle->file, i, 0, remainsize, buf + offset);
				offset += remainsize;
				handle->curpos = remainsize;
			}
		}

		return startpos;
	}
	
#else
	// simply append all documents at the end of file
	

#endif

	return 0;
}

bid_t docio_append_doc(struct docio_handle *handle, struct docio_object *doc)
{
	struct docio_length length;
	uint64_t docsize;
	//uint8_t buf[docsize];
	uint32_t offset = 0;
	bid_t bid;
	void *buf;
	size_t compbuf_len;
	void *compbuf;

	length = doc->length;

	#ifdef _DOC_COMP
		if (doc->length.bodylen > 0) {
			compbuf_len = snappy_max_compressed_length(length.bodylen);
			compbuf = (void *)malloc(compbuf_len);

			snappy_compress(doc->body, length.bodylen, compbuf, &compbuf_len);
			length.bodylen = compbuf_len;
		}
	#endif

	docsize = sizeof(struct docio_length) + length.keylen + length.metalen + length.bodylen;
	buf = (void *)malloc(docsize);

	memcpy(buf + offset, &length, sizeof(struct docio_length));
	offset += sizeof(struct docio_length);

	// copy key
	memcpy(buf + offset, doc->key, length.keylen);
	offset += length.keylen;

	// copy metadata (optional)
	if (length.metalen > 0) {
		memcpy(buf + offset, doc->meta, length.metalen);
		offset += length.metalen;
	}

	// copy body (optional)
	if (length.bodylen > 0) {
		#ifdef _DOC_COMP
			memcpy(buf + offset, compbuf, length.bodylen);
			free(compbuf);
		#else
			memcpy(buf + offset, doc->body, length.bodylen);
		#endif
		offset += length.bodylen;
	}

	bid = docio_append_doc_raw(handle, docsize, buf);
	free(buf);
	
	return bid;
}

uint64_t _docio_read_length(struct docio_handle *handle, uint64_t offset, struct docio_length *length)
{
	bid_t bid = offset / handle->file->blocksize;
	uint32_t pos = offset % handle->file->blocksize;
	uint8_t buf[handle->file->blocksize];
	uint32_t restsize;

	restsize = handle->file->blocksize - pos;
	// read length structure
	filemgr_read(handle->file, bid, buf);
	if (restsize >= sizeof(struct docio_length)) {
		memcpy(length, buf+pos, sizeof(struct docio_length));
		pos += sizeof(struct docio_length);
			
	}else{	
		memcpy(length, buf+pos, restsize);
		// read additional block
		bid++;
		filemgr_read(handle->file, bid, buf);
		// memcpy rest of data
		memcpy(length + restsize, buf, sizeof(struct docio_length) - restsize);
		pos = sizeof(struct docio_length) - restsize;
	}

	return bid*handle->file->blocksize + pos;
}

uint64_t _docio_read_doc_component(struct docio_handle *handle, uint64_t offset, uint32_t len, void *buf_out)
{
	uint32_t rest_len;
	bid_t bid = offset / handle->file->blocksize;
	uint32_t pos = offset % handle->file->blocksize;
	uint8_t buf[handle->file->blocksize];
	uint32_t restsize;

	rest_len = len;

	while(rest_len > 0) {
		filemgr_read(handle->file, bid, buf);
		restsize = handle->file->blocksize - pos;

		if (restsize >= rest_len) {
			memcpy(buf_out + (len - rest_len), buf + pos, rest_len);
			pos += rest_len;
			rest_len = 0;
		}else{
			memcpy(buf_out + (len - rest_len), buf + pos, restsize);
			bid++;
			pos = 0;
			rest_len -= restsize;
		}
	}

	return bid*handle->file->blocksize + pos;
}

#ifdef _DOC_COMP

uint64_t _docio_read_doc_component_comp(struct docio_handle *handle, uint64_t offset, uint32_t *len, void *buf_out)
{
	uint32_t rest_len;
	bid_t bid = offset / handle->file->blocksize;
	uint32_t pos = offset % handle->file->blocksize;
	uint8_t buf[handle->file->blocksize];
	void *temp_buf;
	uint32_t restsize;
	size_t uncomp_size;

	temp_buf = (void *)malloc(*len);
	rest_len = *len;

	while(rest_len > 0) {
		filemgr_read(handle->file, bid, buf);
		restsize = handle->file->blocksize - pos;

		if (restsize >= rest_len) {
			memcpy(temp_buf + (*len - rest_len), buf + pos, rest_len);
			pos += rest_len;
			rest_len = 0;
		}else{
			memcpy(temp_buf + (*len - rest_len), buf + pos, restsize);
			bid++;
			pos = 0;
			rest_len -= restsize;
		}
	}

	snappy_uncompressed_length(temp_buf, *len, &uncomp_size);
	snappy_uncompress(temp_buf, *len, buf_out, &uncomp_size);
	*len = uncomp_size;

	free(temp_buf);

	return bid*handle->file->blocksize + pos;
}

#endif

void docio_read_doc_key(struct docio_handle *handle, uint64_t offset, keylen_t *keylen, void *keybuf)
{
	struct docio_length length;
	uint64_t _offset;

	_offset = _docio_read_length(handle, offset, &length);
	_offset = _docio_read_doc_component(handle, _offset, length.keylen, keybuf);
	*keylen = length.keylen;
}

uint64_t docio_read_doc_key_meta(struct docio_handle *handle, uint64_t offset, struct docio_object *doc)
{
	uint64_t _offset;

	_offset = _docio_read_length(handle, offset, &doc->length);

	if (doc->key == NULL) doc->key = (void *)malloc(doc->length.keylen);
	if (doc->meta == NULL) doc->meta = (void *)malloc(doc->length.metalen);

	_offset = _docio_read_doc_component(handle, _offset, doc->length.keylen, doc->key);
	_offset = _docio_read_doc_component(handle, _offset, doc->length.metalen, doc->meta);

	return _offset;
}

void docio_read_doc(struct docio_handle *handle, uint64_t offset, struct docio_object *doc)
{
	uint64_t _offset;
	
	_offset = _docio_read_length(handle, offset, &doc->length);

	if (doc->key == NULL) doc->key = (void *)malloc(doc->length.keylen);
	if (doc->meta == NULL) doc->meta = (void *)malloc(doc->length.metalen);
	if (doc->body == NULL) doc->body = (void *)malloc(doc->length.bodylen);

	_offset = _docio_read_doc_component(handle, _offset, doc->length.keylen, doc->key);
	_offset = _docio_read_doc_component(handle, _offset, doc->length.metalen, doc->meta);
	#ifdef _DOC_COMP
		_offset = _docio_read_doc_component_comp(handle, _offset, &doc->length.bodylen, doc->body);		
	#else
		_offset = _docio_read_doc_component(handle, _offset, doc->length.bodylen, doc->body);		
	#endif
}

